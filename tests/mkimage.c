
#include "forge/fg_common.h"
#include "forge/fg_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR    512u
#define SPC       8u
#define RESERVED  32u
#define NUM_FATS  2u

static uint8_t *g_img;
static uint64_t g_size;
static uint32_t g_spf;
static uint64_t g_part_lba = 2048;
static uint64_t g_vol;
static uint64_t g_data;
static uint32_t g_total_clusters;
static uint32_t g_next_cluster = 3;
static uint32_t g_dirent = 0;

static void wr16(uint64_t off, uint16_t v) { g_img[off] = (uint8_t)v; g_img[off+1] = (uint8_t)(v>>8); }
static void wr32(uint64_t off, uint32_t v)
{
    g_img[off] = (uint8_t)v; g_img[off+1] = (uint8_t)(v>>8);
    g_img[off+2] = (uint8_t)(v>>16); g_img[off+3] = (uint8_t)(v>>24);
}

static uint64_t clus_off(uint32_t c) { return g_data + (uint64_t)(c - 2) * SPC * SECTOR; }

static void fat_set(uint32_t clus, uint32_t val)
{
    uint32_t f;
    for (f = 0; f < NUM_FATS; f++) {
        uint64_t base = g_vol + (uint64_t)(RESERVED + f * g_spf) * SECTOR;
        wr32(base + (uint64_t)clus * 4, val & 0x0FFFFFFFu);
    }
}


static uint32_t adler32(const uint8_t *p, size_t n)
{
    uint32_t a = 1, b = 0;
    size_t i;
    for (i = 0; i < n; i++) { a = (a + p[i]) % 65521; b = (b + a) % 65521; }
    return (b << 16) | a;
}

static size_t make_png(uint8_t *o, const char *label)
{
    static const uint8_t raw[4] = { 0x00, 0xE3, 0x2C, 0x4F };
    size_t n = 0;
    uint32_t crc;
    memcpy(o, "\x89PNG\r\n\x1a\n", 8); n = 8;
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=13;
    memcpy(o+n, "IHDR", 4);
    o[n+4]=0;o[n+5]=0;o[n+6]=0;o[n+7]=1;
    o[n+8]=0;o[n+9]=0;o[n+10]=0;o[n+11]=1;
    o[n+12]=8; o[n+13]=2; o[n+14]=0; o[n+15]=0; o[n+16]=0;
    crc = fg_crc32(0, o+n, 17);
    o[n+17]=(uint8_t)(crc>>24);o[n+18]=(uint8_t)(crc>>16);
    o[n+19]=(uint8_t)(crc>>8);o[n+20]=(uint8_t)crc;
    n += 21;
    {
        uint8_t z[16];
        size_t zn = 0;
        uint32_t ad = adler32(raw, sizeof raw);
        z[zn++]=0x78; z[zn++]=0x01;
        z[zn++]=0x01; z[zn++]=0x04; z[zn++]=0x00; z[zn++]=0xFB; z[zn++]=0xFF;
        memcpy(z+zn, raw, sizeof raw); zn += sizeof raw;
        z[zn++]=(uint8_t)(ad>>24); z[zn++]=(uint8_t)(ad>>16);
        z[zn++]=(uint8_t)(ad>>8);  z[zn++]=(uint8_t)ad;
        o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=(uint8_t)zn;
        memcpy(o+n, "IDAT", 4);
        memcpy(o+n+4, z, zn);
        crc = fg_crc32(0, o+n, 4+zn);
        o[n+4+zn]=(uint8_t)(crc>>24);o[n+5+zn]=(uint8_t)(crc>>16);
        o[n+6+zn]=(uint8_t)(crc>>8); o[n+7+zn]=(uint8_t)crc;
        n += 8 + zn;
    }
    {
        size_t kl = 7 + 1 + strlen(label);
        o[n++]=(uint8_t)(kl>>24);o[n++]=(uint8_t)(kl>>16);
        o[n++]=(uint8_t)(kl>>8); o[n++]=(uint8_t)kl;
        memcpy(o+n, "tEXt", 4);
        memcpy(o+n+4, "Comment", 7);
        o[n+11] = 0;
        memcpy(o+n+12, label, strlen(label));
        crc = fg_crc32(0, o+n, 4 + kl);
        o[n+4+kl]=(uint8_t)(crc>>24);o[n+5+kl]=(uint8_t)(crc>>16);
        o[n+6+kl]=(uint8_t)(crc>>8); o[n+7+kl]=(uint8_t)crc;
        n += 8 + kl;
    }
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
    memcpy(o+n, "IEND", 4);
    crc = fg_crc32(0, o+n, 4);
    o[n+4]=(uint8_t)(crc>>24);o[n+5]=(uint8_t)(crc>>16);
    o[n+6]=(uint8_t)(crc>>8); o[n+7]=(uint8_t)crc;
    n += 8;
    return n;
}

static size_t make_jpeg(uint8_t *o, size_t payload)
{
    size_t n = 0, i;
    o[n++]=0xFF; o[n++]=0xD8;
    o[n++]=0xFF; o[n++]=0xE0; o[n++]=0x00; o[n++]=0x10;
    memcpy(o+n, "JFIF\0", 5); n += 5;
    o[n++]=1; o[n++]=1; o[n++]=0; o[n++]=0; o[n++]=1; o[n++]=0; o[n++]=1;
    o[n++]=0; o[n++]=0;
    o[n++]=0xFF; o[n++]=0xDA; o[n++]=0x00; o[n++]=0x08;
    o[n++]=1; o[n++]=1; o[n++]=0; o[n++]=0; o[n++]=63; o[n++]=0;
    for (i = 0; i < payload; i++) {
        uint8_t b = (uint8_t)(0x40 + ((i * 37) & 0x7F));
        if (b == 0xFF) b = 0x7E;
        o[n++] = b;
    }
    o[n++]=0xFF; o[n++]=0xD9;
    return n;
}

static size_t make_pdf(uint8_t *o, const char *text)
{
    return (size_t)sprintf((char *)o,
        "%%PDF-1.4\n"
        "1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
        "3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 80]"
        "/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
        "4 0 obj<</Length 70>>stream\n"
        "BT /F1 12 Tf 20 40 Td (%s) Tj ET\n"
        "endstream endobj\n"
        "5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
        "trailer<</Root 1 0 R/Size 6>>\n"
        "startxref\n0\n"
        "%%%%EOF\n", text);
}

static size_t make_zip(uint8_t *o, const char *name, const char *body)
{
    size_t nl = strlen(name), bl = strlen(body), n = 0, lfh;
    uint32_t crc = fg_crc32(0, body, bl);
    lfh = 0;
    memcpy(o, "PK\x03\x04", 4);
    o[4]=20;o[5]=0;o[6]=0;o[7]=0;o[8]=0;o[9]=0;
    o[10]=0;o[11]=0;o[12]=0;o[13]=0;
    o[14]=(uint8_t)crc;o[15]=(uint8_t)(crc>>8);o[16]=(uint8_t)(crc>>16);o[17]=(uint8_t)(crc>>24);
    o[18]=(uint8_t)bl;o[19]=(uint8_t)(bl>>8);o[20]=0;o[21]=0;
    o[22]=(uint8_t)bl;o[23]=(uint8_t)(bl>>8);o[24]=0;o[25]=0;
    o[26]=(uint8_t)nl;o[27]=0;o[28]=0;o[29]=0;
    memcpy(o+30, name, nl);
    memcpy(o+30+nl, body, bl);
    n = 30 + nl + bl;
    {
        size_t cd = n;
        memcpy(o+n, "PK\x01\x02", 4);
        o[n+4]=20;o[n+5]=0;o[n+6]=20;o[n+7]=0;
        memset(o+n+8, 0, 8);
        o[n+16]=(uint8_t)crc;o[n+17]=(uint8_t)(crc>>8);
        o[n+18]=(uint8_t)(crc>>16);o[n+19]=(uint8_t)(crc>>24);
        o[n+20]=(uint8_t)bl;o[n+21]=(uint8_t)(bl>>8);o[n+22]=0;o[n+23]=0;
        o[n+24]=(uint8_t)bl;o[n+25]=(uint8_t)(bl>>8);o[n+26]=0;o[n+27]=0;
        o[n+28]=(uint8_t)nl;o[n+29]=0;
        memset(o+n+30, 0, 12);
        o[n+42]=(uint8_t)lfh;o[n+43]=0;o[n+44]=0;o[n+45]=0;
        memcpy(o+n+46, name, nl);
        n += 46 + nl;
        memcpy(o+n, "PK\x05\x06", 4);
        o[n+4]=0;o[n+5]=0;o[n+6]=0;o[n+7]=0;
        o[n+8]=1;o[n+9]=0;o[n+10]=1;o[n+11]=0;
        {
            uint32_t cds = (uint32_t)(n - cd), cdo = (uint32_t)cd;
            o[n+12]=(uint8_t)cds;o[n+13]=(uint8_t)(cds>>8);
            o[n+14]=(uint8_t)(cds>>16);o[n+15]=(uint8_t)(cds>>24);
            o[n+16]=(uint8_t)cdo;o[n+17]=(uint8_t)(cdo>>8);
            o[n+18]=(uint8_t)(cdo>>16);o[n+19]=(uint8_t)(cdo>>24);
        }
        o[n+20]=0;o[n+21]=0;
        n += 22;
    }
    return n;
}

static size_t make_gif(uint8_t *o, uint8_t tint)
{
    static const uint8_t g[] = {
        'G','I','F','8','9','a', 1,0, 1,0, 0x80,0,0,
        0xFF,0xFF,0xFF, 0x00,0x00,0x00,
        0x2C, 0,0, 0,0, 1,0, 1,0, 0,
        0x02, 0x02, 0x44, 0x01, 0x00,
        0x3B };
    memcpy(o, g, sizeof g);
    o[16] = tint;
    return sizeof g;
}

static size_t make_sqlite(uint8_t *o)
{
    memset(o, 0, 8192);
    memcpy(o, "SQLite format 3\0", 16);
    o[16] = 0x10; o[17] = 0x00;
    o[18] = 1; o[19] = 1; o[20] = 0;
    o[21] = 64; o[22] = 32; o[23] = 32;
    o[28] = 0; o[29] = 0; o[30] = 0; o[31] = 2;
    memcpy(o + 100, "FORGE synthetic evidence database", 34);
    return 8192;
}

typedef struct {
    char     name[32];
    uint64_t off;
    uint64_t size;
    char     sha[65];
    const char *kind;
} planted;

static planted g_planted[64];
static int g_nplanted;

static void record(const char *name, uint64_t off, const uint8_t *data,
                   uint64_t size, const char *kind)
{
    planted *p = &g_planted[g_nplanted++];
    snprintf(p->name, sizeof p->name, "%s", name);
    p->off = off;
    p->size = size;
    p->kind = kind;
    fg_sha256_hex(data, (size_t)size, p->sha);
}


static void add_file(const char *sfn, const uint8_t *data, size_t len, int deleted)
{
    uint32_t clusters = (uint32_t)((len + SPC * SECTOR - 1) / (SPC * SECTOR));
    uint32_t first = g_next_cluster, c;
    uint64_t de;
    size_t left = len;
    const uint8_t *p = data;

    if (!clusters) clusters = 1;
    for (c = 0; c < clusters; c++) {
        uint32_t cl = first + c;
        uint64_t off = clus_off(cl);
        size_t take = left > SPC * SECTOR ? SPC * SECTOR : left;
        memcpy(g_img + off, p, take);
        p += take;
        left -= take;
        fat_set(cl, (c + 1 < clusters) ? cl + 1 : 0x0FFFFFFFu);
    }
    g_next_cluster += clusters;

    de = clus_off(2) + (uint64_t)g_dirent * 32;
    g_dirent++;
    memset(g_img + de, ' ', 11);
    {
        const char *dot = strchr(sfn, '.');
        size_t bn = dot ? (size_t)(dot - sfn) : strlen(sfn);
        size_t i;
        for (i = 0; i < bn && i < 8; i++)
            g_img[de + i] = (uint8_t)(sfn[i] >= 'a' && sfn[i] <= 'z' ? sfn[i] - 32 : sfn[i]);
        if (dot) for (i = 0; i < 3 && dot[1 + i]; i++)
            g_img[de + 8 + i] = (uint8_t)(dot[1+i] >= 'a' && dot[1+i] <= 'z'
                                          ? dot[1+i] - 32 : dot[1+i]);
    }
    g_img[de + 11] = 0x20;
    wr16(de + 22, 0x8000); wr16(de + 24, 0x5A00);
    wr16(de + 20, (uint16_t)(first >> 16));
    wr16(de + 26, (uint16_t)(first & 0xFFFF));
    wr32(de + 28, (uint32_t)len);

    if (deleted) {
        g_img[de] = 0xE5;
        for (c = 0; c < clusters; c++) fat_set(first + c, 0);
        record(sfn, clus_off(first), data, len, "deleted");
    } else {
        record(sfn, clus_off(first), data, len, "live");
    }
}

static void add_orphan(const char *label, const uint8_t *data, size_t len)
{
    uint32_t clusters = (uint32_t)((len + SPC * SECTOR - 1) / (SPC * SECTOR));
    uint64_t off;
    if (!clusters) clusters = 1;
    g_next_cluster += 2;
    off = clus_off(g_next_cluster);
    memcpy(g_img + off, data, len);
    g_next_cluster += clusters;
    record(label, off, data, len, "orphan");
}

static void add_fragmented(const char *label, const uint8_t *data, size_t len)
{
    uint32_t cl;
    uint64_t off1, off2;
    size_t head = SPC * SECTOR;
    if (len <= head) head = len / 2;
    g_next_cluster += 2;
    cl = g_next_cluster;
    off1 = clus_off(cl);
    memcpy(g_img + off1, data, head);
    {
        uint32_t k;
        uint8_t *g = g_img + clus_off(cl + 1);
        for (k = 0; k < SPC * SECTOR; k++)
            g[k] = (uint8_t)((k * 1103515245u + 12345u) >> 16);
    }
    off2 = clus_off(cl + 2);
    memcpy(g_img + off2, data + head, len - head);
    g_next_cluster += 3 + (uint32_t)((len - head) / (SPC * SECTOR));
    record(label, off1, data, len, "fragmented");
}


int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "forge_test.img";
    uint64_t mib = argc > 2 ? strtoull(argv[2], NULL, 10) : 64;
    uint64_t total_sectors;
    FILE *f;
    uint8_t *tmp;
    int i;

    g_size = mib * 1024 * 1024;
    g_img = (uint8_t *)calloc(1, (size_t)g_size);
    tmp = (uint8_t *)malloc(1 << 20);
    if (!g_img || !tmp) { fprintf(stderr, "out of memory\n"); return 1; }

    g_vol = g_part_lba * SECTOR;
    total_sectors = (g_size - g_vol) / SECTOR;
    g_spf = (uint32_t)(((total_sectors - RESERVED) / SPC * 4 + SECTOR - 1) / SECTOR) + 2;
    g_data = g_vol + (uint64_t)(RESERVED + NUM_FATS * g_spf) * SECTOR;
    g_total_clusters = (uint32_t)((g_size - g_data) / (SPC * SECTOR));

    g_img[446 + 0] = 0x80;
    g_img[446 + 4] = 0x0C;
    wr32(446 + 8, (uint32_t)g_part_lba);
    wr32(446 + 12, (uint32_t)total_sectors);
    g_img[510] = 0x55; g_img[511] = 0xAA;

    
    g_img[g_vol + 0] = 0xEB; g_img[g_vol + 1] = 0x58; g_img[g_vol + 2] = 0x90;
    memcpy(g_img + g_vol + 3, "FORGE  ", 8);
    wr16(g_vol + 11, SECTOR);
    g_img[g_vol + 13] = SPC;
    wr16(g_vol + 14, RESERVED);
    g_img[g_vol + 16] = NUM_FATS;
    wr16(g_vol + 17, 0);
    wr16(g_vol + 19, 0);
    g_img[g_vol + 21] = 0xF8;
    wr16(g_vol + 22, 0);
    wr16(g_vol + 24, 63);
    wr16(g_vol + 26, 255);
    wr32(g_vol + 28, (uint32_t)g_part_lba);
    wr32(g_vol + 32, (uint32_t)total_sectors);
    wr32(g_vol + 36, g_spf);
    wr32(g_vol + 44, 2);
    wr16(g_vol + 48, 1);
    wr16(g_vol + 50, 6);
    g_img[g_vol + 64] = 0x80;
    g_img[g_vol + 66] = 0x29;
    wr32(g_vol + 67, 0x4B415643u);
    memcpy(g_img + g_vol + 71, "FORGE TEST", 11);
    memcpy(g_img + g_vol + 82, "FAT32   ", 8);
    g_img[g_vol + 510] = 0x55; g_img[g_vol + 511] = 0xAA;
    memcpy(g_img + g_vol + 6 * SECTOR, g_img + g_vol, SECTOR);

    fat_set(0, 0x0FFFFFF8u);
    fat_set(1, 0x0FFFFFFFu);
    fat_set(2, 0x0FFFFFFFu);

    memset(g_img + clus_off(2), ' ', 11);
    memcpy(g_img + clus_off(2), "FORGE TEST", 11);
    g_img[clus_off(2) + 11] = 0x08;
    g_dirent = 1;


    { size_t n = make_pdf(tmp, "Live case notes - must NOT be recovered");
      add_file("live.pdf", tmp, n, 0); }
    { size_t n = make_png(tmp, "live wallpaper"); add_file("live.png", tmp, n, 0); }

    { size_t n = make_pdf(tmp, "Deleted interview transcript, case 2026-114");
      add_file("secret.pdf", tmp, n, 1); }
    { size_t n = make_png(tmp, "seized handset screenshot"); add_file("evidence.png", tmp, n, 1); }
    { size_t n = make_gif(tmp, 0x11); add_file("badge.gif", tmp, n, 1); }
    { size_t n = make_zip(tmp, "notes.txt",
        "Deleted archive contents: suspect ledger extract");
      add_file("ledger.zip", tmp, n, 1); }
    { size_t n = make_jpeg(tmp, 9000); add_file("photo.jpg", tmp, n, 1); }
    { size_t n = make_sqlite(tmp); add_file("chat.db", tmp, n, 1); }
    { size_t n = (size_t)sprintf((char *)tmp,
        "%%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n"
        "startxref\n0\n%%%%EOF\n");
      add_file("memo.pdf", tmp, n, 1); }

    { size_t n = make_pdf(tmp, "Orphaned draft with no directory entry");
      add_orphan("orphan.pdf", tmp, n); }
    { size_t n = make_png(tmp, "orphaned body, no directory entry"); add_orphan("orphan.png", tmp, n); }
    { size_t n = make_zip(tmp, "payload.bin", "orphaned archive body");
      add_orphan("orphan.zip", tmp, n); }
    { size_t n = make_gif(tmp, 0x22); add_orphan("orphan.gif", tmp, n); }


    { size_t n = make_jpeg(tmp, 12000); add_fragmented("split.jpg", tmp, n); }

    f = fopen(path, "wb");
    if (!f) { perror(path); return 1; }
    fwrite(g_img, 1, (size_t)g_size, f);
    fclose(f);

    printf("Wrote %s (%llu MiB)\n", path, (unsigned long long)mib);
    printf("  MBR + FAT32 volume at LBA %llu, %u clusters of %u bytes\n\n",
           (unsigned long long)g_part_lba, g_total_clusters, SPC * SECTOR);
    printf("  %-14s %-12s %10s  %s\n", "NAME", "STATE", "SIZE", "SHA-256");
    for (i = 0; i < g_nplanted; i++)
        printf("  %-14s %-12s %10llu  %s\n", g_planted[i].name, g_planted[i].kind,
               (unsigned long long)g_planted[i].size, g_planted[i].sha);
    printf("\n  %d artefacts planted. Files marked 'live' must not appear in a\n"
           "  recovery report; every other row should.\n\n", g_nplanted);


    {
        char mpath[1024];
        FILE *mf;
        snprintf(mpath, sizeof mpath, "%s.manifest.csv", path);
        mf = fopen(mpath, "wb");
        if (mf) {
            fprintf(mf, "name,state,offset,size,sha256\n");
            for (i = 0; i < g_nplanted; i++)
                fprintf(mf, "%s,%s,%llu,%llu,%s\n", g_planted[i].name,
                        g_planted[i].kind, (unsigned long long)g_planted[i].off,
                        (unsigned long long)g_planted[i].size, g_planted[i].sha);
            fclose(mf);
            printf("  Manifest: %s\n\n", mpath);
        }
    }
    free(g_img);
    free(tmp);
    return 0;
}
