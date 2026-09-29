
#include "fs_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint32_t bytes_per_sector;
    uint32_t cluster_size;
    uint64_t fat_start;        /* device byte offset                          */
    uint64_t fat_size;
    uint64_t root_start;       /* FAT12/16 fixed root dir, 0 on FAT32         */
    uint32_t root_entries;
    uint64_t data_start;       /* byte offset of cluster 2                    */
    uint32_t root_cluster;     /* FAT32                                       */
    uint64_t total_clusters;
    fg_fs_kind kind;
} fat_vol;

static uint64_t fat_clus_off(const fat_vol *v, uint64_t clus)
{
    return v->data_start + (clus - 2) * v->cluster_size;
}

static int fat_read_bpb(fg_fs_ctx *c, fat_vol *v, fg_fs_kind kind)
{
    uint8_t b[512];
    size_t got = 0;
    uint32_t spf, rsv, nfat, rde, tot, root_sec, data_sec;
    uint8_t spc;

    if (fg_dev_pread(c->dev, b, sizeof b, c->vol_off, &got) != FG_OK || got < 512)
        return 0;
    memset(v, 0, sizeof *v);
    v->kind = kind;
    v->bytes_per_sector = fg_rd16le(b + 11);
    spc = b[13];
    rsv = fg_rd16le(b + 14);
    nfat = b[16];
    rde = fg_rd16le(b + 17);
    spf = fg_rd16le(b + 22);
    if (!spf) spf = fg_rd32le(b + 36);
    tot = fg_rd16le(b + 19);
    if (!tot) tot = fg_rd32le(b + 32);
    if (!v->bytes_per_sector || !spc || !nfat || !spf || !tot) return 0;

    v->cluster_size = v->bytes_per_sector * spc;
    v->fat_start = c->vol_off + (uint64_t)rsv * v->bytes_per_sector;
    v->fat_size  = (uint64_t)spf * v->bytes_per_sector;
    root_sec = ((uint32_t)rde * 32 + v->bytes_per_sector - 1) / v->bytes_per_sector;
    if (kind == FG_FS_FAT32) {
        v->root_cluster = fg_rd32le(b + 44);
        root_sec = 0;
        v->root_entries = 0;
    } else {
        v->root_start = v->fat_start + (uint64_t)nfat * v->fat_size;
        v->root_entries = rde;
    }
    v->data_start = v->fat_start + (uint64_t)nfat * v->fat_size +
                    (uint64_t)root_sec * v->bytes_per_sector;
    data_sec = tot - (rsv + nfat * spf + root_sec);
    v->total_clusters = data_sec / spc;
    return 1;
}

/* Short 8.3 name from a directory entry, with the deleted first byte
 * replaced by '_' since the original character is genuinely gone. */
static void fat_sfn(const uint8_t *e, char *out, size_t outsz)
{
    char base[9], ext[4];
    int i, n = 0;
    for (i = 0; i < 8; i++) if (e[i] != ' ') n = i + 1;
    memcpy(base, e, 8);
    base[n > 0 ? n : 0] = '\0';
    if (n <= 0) base[0] = '\0';
    n = 0;
    for (i = 0; i < 3; i++) if (e[8 + i] != ' ') n = i + 1;
    memcpy(ext, e + 8, 3);
    ext[n > 0 ? n : 0] = '\0';
    if (n <= 0) ext[0] = '\0';
    if (base[0] == (char)0xE5) base[0] = '_';
    if (ext[0]) snprintf(out, outsz, "%s.%s", base, ext);
    else        snprintf(out, outsz, "%s", base);
}

static int64_t fat_time(uint16_t date, uint16_t tm)
{
    /* Days since epoch from a FAT date, without <time.h> mktime's timezone. */
    static const int mdays[12] = {0,31,59,90,120,151,181,212,243,273,304,334};
    int y = 1980 + ((date >> 9) & 0x7F);
    int mo = (date >> 5) & 0x0F;
    int d  = date & 0x1F;
    int64_t days, leaps;
    int yy;
    if (mo < 1 || mo > 12 || d < 1) return 0;
    days = 0;
    for (yy = 1970; yy < y; yy++)
        days += ((yy % 4 == 0 && yy % 100 != 0) || yy % 400 == 0) ? 366 : 365;
    days += mdays[mo - 1] + (d - 1);
    leaps = ((y % 4 == 0 && y % 100 != 0) || y % 400 == 0) && mo > 2;
    days += leaps;
    return days * 86400 + ((tm >> 11) & 0x1F) * 3600 +
           ((tm >> 5) & 0x3F) * 60 + (tm & 0x1F) * 2;
}

/* Walk a directory region (a fixed root or a cluster-chained directory) and
 * emit every deleted entry. Recursion follows subdirectories that are still
 * live so deleted files inside them are found too. */
static void fat_scan_dir(fg_fs_ctx *c, const fat_vol *v, uint64_t off,
                         uint64_t bytes, int depth)
{
    uint8_t *buf;
    uint64_t i;
    size_t got = 0;
    char lfn[512];
    int have_lfn = 0;

    if (depth > 12 || !bytes || bytes > 64ull * 1024 * 1024) return;
    buf = (uint8_t *)malloc((size_t)bytes);
    if (!buf) return;
    if (fg_dev_pread(c->dev, buf, (size_t)bytes, off, &got) != FG_OK || got < 32) {
        free(buf);
        return;
    }
    lfn[0] = '\0';

    for (i = 0; i + 32 <= got; i += 32) {
        const uint8_t *e = buf + i;
        uint8_t attr = e[11];
        uint32_t clus, size;
        char name[512];

        if (!e[0]) break;                        /* end of directory          */

        if (attr == 0x0F) {                      /* long file name chunk      */
            uint8_t seq = e[0] & 0x3F;
            uint16_t chunk[13];
            char part[64];
            int k;
            if (!seq || seq > 20) continue;
            for (k = 0; k < 5; k++)  chunk[k]     = fg_rd16le(e + 1 + k * 2);
            for (k = 0; k < 6; k++)  chunk[5 + k] = fg_rd16le(e + 14 + k * 2);
            for (k = 0; k < 2; k++)  chunk[11 + k]= fg_rd16le(e + 28 + k * 2);
            fg_utf16le_to_utf8((const uint8_t *)chunk, 13, part, sizeof part);
            if (e[0] & 0x40) { snprintf(lfn, sizeof lfn, "%s", part); }
            else {
                char tmp[512];
                snprintf(tmp, sizeof tmp, "%s%s", part, lfn);
                snprintf(lfn, sizeof lfn, "%s", tmp);
            }
            have_lfn = 1;
            continue;
        }

        clus = ((uint32_t)fg_rd16le(e + 20) << 16) | fg_rd16le(e + 26);
        size = fg_rd32le(e + 28);

        if (e[0] == 0xE5) {
            fg_run run;
            int64_t mt;
            if (attr & 0x08) { have_lfn = 0; lfn[0] = '\0'; continue; }  /* volume label */
            if (attr & 0x10) { have_lfn = 0; lfn[0] = '\0'; continue; }  /* directory    */
            if (!clus || !size || clus >= v->total_clusters + 2) {
                have_lfn = 0; lfn[0] = '\0';
                continue;
            }
            if (have_lfn && lfn[0]) snprintf(name, sizeof name, "%s", lfn);
            else fat_sfn(e, name, sizeof name);
            mt = fat_time(fg_rd16le(e + 24), fg_rd16le(e + 22));
            /* The FAT chain is gone, so assume contiguity - the standard
             * assumption for FAT recovery, flagged in the confidence score. */
            run.off = fat_clus_off(v, clus);
            run.len = size;
            fg_fs_emit(c, name, v->kind, &run, 1, NULL, size, mt, 1, 0);
        } else if ((attr & 0x10) && e[0] != '.' && depth < 12) {
            /* live subdirectory: descend to find deleted entries inside */
            if (clus >= 2 && clus < v->total_clusters + 2)
                fat_scan_dir(c, v, fat_clus_off(v, clus),
                             (uint64_t)v->cluster_size * 8, depth + 1);
        }
        have_lfn = 0;
        lfn[0] = '\0';
    }
    free(buf);
}

fg_status fg_fat_recover(fg_fs_ctx *c, fg_fs_kind kind)
{
    fat_vol v;
    if (!fat_read_bpb(c, &v, kind)) return FG_ERR_NOTFOUND;
    c->cluster_size = v.cluster_size;

    if (kind == FG_FS_FAT32) {
        if (v.root_cluster < 2) return FG_ERR_CORRUPT;
        fat_scan_dir(c, &v, fat_clus_off(&v, v.root_cluster),
                     (uint64_t)v.cluster_size * 16, 0);
    } else {
        fat_scan_dir(c, &v, v.root_start, (uint64_t)v.root_entries * 32, 0);
    }
    return FG_OK;
}

/* ========================================================================== */
/*  exFAT                                                                     */
/* ========================================================================== */
/* Directory entries come in sets: 0x85 file, 0xC0 stream extension (size and
 * first cluster), 0xC1 file name fragments. Deleted entries have the high
 * "in use" bit (0x80) cleared, so 0x85 becomes 0x05. */
fg_status fg_exfat_recover(fg_fs_ctx *c)
{
    uint8_t b[512];
    size_t got = 0;
    uint64_t fat_off, clus_heap, root_clus, data_start;
    uint32_t cluster_size, sector_size;
    uint8_t *dir;
    uint64_t dirbytes;
    uint64_t i;

    if (fg_dev_pread(c->dev, b, sizeof b, c->vol_off, &got) != FG_OK || got < 512)
        return FG_ERR_IO;
    if (memcmp(b + 3, "EXFAT   ", 8)) return FG_ERR_NOTFOUND;

    sector_size  = 1u << b[108];
    cluster_size = sector_size * (1u << b[109]);
    fat_off      = c->vol_off + (uint64_t)fg_rd32le(b + 80) * sector_size;
    clus_heap    = (uint64_t)fg_rd32le(b + 88);
    root_clus    = (uint64_t)fg_rd32le(b + 96);
    FG_UNUSED(fat_off);
    if (!sector_size || !cluster_size || root_clus < 2) return FG_ERR_CORRUPT;
    data_start = c->vol_off + clus_heap * sector_size;
    c->cluster_size = cluster_size;

    dirbytes = (uint64_t)cluster_size * 16;
    if (dirbytes > 16ull * 1024 * 1024) dirbytes = 16ull * 1024 * 1024;
    dir = (uint8_t *)malloc((size_t)dirbytes);
    if (!dir) return FG_ERR_NOMEM;
    if (fg_dev_pread(c->dev, dir, (size_t)dirbytes,
                     data_start + (root_clus - 2) * cluster_size, &got) != FG_OK) {
        free(dir);
        return FG_ERR_IO;
    }

    for (i = 0; i + 32 <= got; i += 32) {
        const uint8_t *e = dir + i;
        if (e[0] == 0x05 || e[0] == 0x85) {           /* file entry           */
            int deleted = (e[0] == 0x05);
            uint8_t secondary = e[1];
            uint16_t attrs = fg_rd16le(e + 4);
            int64_t mt = 0;
            char name[512] = "";
            uint64_t size = 0, first = 0;
            int nofat = 0;
            uint64_t j;
            size_t namepos = 0;
            uint16_t wname[256];

            if (!deleted) continue;
            if (attrs & 0x10) continue;               /* directory            */
            /* exFAT timestamp: DOS-style packed date/time at offset 12 */
            mt = fat_time(fg_rd16le(e + 10), fg_rd16le(e + 8));

            for (j = 1; j <= secondary && i + j * 32 + 32 <= got; j++) {
                const uint8_t *s = dir + i + j * 32;
                if (s[0] == 0x40 || s[0] == 0xC0) {   /* stream extension     */
                    nofat = (s[1] & 0x02) ? 1 : 0;
                    size  = fg_rd64le(s + 24);
                    first = fg_rd32le(s + 20);
                } else if (s[0] == 0x41 || s[0] == 0xC1) {  /* name fragment  */
                    int k;
                    for (k = 0; k < 15 && namepos < 255; k++)
                        wname[namepos++] = fg_rd16le(s + 2 + k * 2);
                }
            }
            i += (uint64_t)secondary * 32;
            if (!size || first < 2) continue;
            if (namepos) fg_utf16le_to_utf8((const uint8_t *)wname, (int)namepos,
                                            name, sizeof name);
            if (!name[0]) snprintf(name, sizeof name, "exfat_%llu.bin",
                                   (unsigned long long)first);
            {
                fg_run run;
                run.off = data_start + (first - 2) * cluster_size;
                run.len = size;
                fg_fs_emit(c, name, FG_FS_EXFAT, &run, 1, NULL, size, mt, 1, !nofat);
            }
        }
    }
    free(dir);
    return FG_OK;
}

/* ========================================================================== */
/*  allocation map dispatch                                                   */
/* ========================================================================== */
fg_status fg_alloc_map_load(fg_fs_ctx *c, fg_fs_kind kind, fg_alloc_map *m)
{
    memset(m, 0, sizeof *m);
    if (kind == FG_FS_NTFS) return fg_ntfs_load_bitmap(c, m);

    if (kind == FG_FS_FAT12 || kind == FG_FS_FAT16 || kind == FG_FS_FAT32) {
        fat_vol v;
        uint8_t *fat;
        uint64_t i, n;
        size_t got = 0;
        if (!fat_read_bpb(c, &v, kind)) return FG_ERR_NOTFOUND;
        if (v.fat_size > 128ull * 1024 * 1024) return FG_ERR_UNSUPPORTED;
        fat = (uint8_t *)malloc((size_t)v.fat_size);
        if (!fat) return FG_ERR_NOMEM;
        if (fg_dev_pread(c->dev, fat, (size_t)v.fat_size, v.fat_start, &got) != FG_OK) {
            free(fat);
            return FG_ERR_IO;
        }
        n = v.total_clusters + 2;
        m->bits = (uint8_t *)fg_xcalloc((size_t)(n + 7) / 8, 1);
        if (!m->bits) { free(fat); return FG_ERR_NOMEM; }
        for (i = 2; i < n; i++) {
            uint32_t ent = 0;
            if (kind == FG_FS_FAT32) {
                if (i * 4 + 4 > got) break;
                ent = fg_rd32le(fat + i * 4) & 0x0FFFFFFFu;
            } else if (kind == FG_FS_FAT16) {
                if (i * 2 + 2 > got) break;
                ent = fg_rd16le(fat + i * 2);
            } else {
                uint64_t byte = i * 3 / 2;
                if (byte + 2 > got) break;
                ent = (i & 1) ? (fg_rd16le(fat + byte) >> 4)
                              : (fg_rd16le(fat + byte) & 0x0FFF);
            }
            if (ent) m->bits[(i - 2) >> 3] |= (uint8_t)(1u << ((i - 2) & 7));
        }
        m->cluster_size = v.cluster_size;
        m->cluster_count = v.total_clusters;
        m->data_start = v.data_start;
        m->valid = 1;
        free(fat);
        return FG_OK;
    }
    return FG_ERR_UNSUPPORTED;
}
