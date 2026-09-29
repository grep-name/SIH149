/* parts.c - MBR and GPT partition table parsing plus filesystem fingerprinting.
 * Read-only.
 */
#include "forge/fg_fs.h"
#include "fs_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

const char *fg_fs_kind_name(fg_fs_kind k)
{
    switch (k) {
    case FG_FS_NTFS:    return "NTFS";
    case FG_FS_FAT12:   return "FAT12";
    case FG_FS_FAT16:   return "FAT16";
    case FG_FS_FAT32:   return "FAT32";
    case FG_FS_EXFAT:   return "exFAT";
    case FG_FS_EXT2:    return "ext2";
    case FG_FS_EXT3:    return "ext3";
    case FG_FS_EXT4:    return "ext4";
    case FG_FS_HFSPLUS: return "HFS+";
    case FG_FS_APFS:    return "APFS";
    case FG_FS_XFS:     return "XFS";
    case FG_FS_BTRFS:   return "Btrfs";
    case FG_FS_ISO9660: return "ISO 9660";
    case FG_FS_UDF:     return "UDF";
    default:            return "unknown";
    }
}

/* `boot` must hold at least the first 2 KiB of the volume; ext superblocks
 * live at offset 1024 so the caller should pass 4 KiB when it can. */
fg_fs_kind fg_fs_identify(const uint8_t *boot, size_t n, char *label, size_t labsz)
{
    if (label && labsz) label[0] = '\0';
    if (n < 512) return FG_FS_UNKNOWN;

    if (!memcmp(boot + 3, "NTFS    ", 8)) {
        if (label && labsz) snprintf(label, labsz, "NTFS volume");
        return FG_FS_NTFS;
    }
    if (!memcmp(boot + 3, "EXFAT   ", 8)) return FG_FS_EXFAT;
    if (n >= 90 && !memcmp(boot + 82, "FAT32   ", 8)) return FG_FS_FAT32;
    if (n >= 62 && !memcmp(boot + 54, "FAT16   ", 8)) return FG_FS_FAT16;
    if (n >= 62 && !memcmp(boot + 54, "FAT12   ", 8)) return FG_FS_FAT12;
    if (n >= 62 && !memcmp(boot + 54, "FAT     ", 8)) {
        /* Decide from the cluster count. */
        uint16_t bps = fg_rd16le(boot + 11);
        uint8_t  spc = boot[13];
        uint16_t rsv = fg_rd16le(boot + 14);
        uint16_t rde = fg_rd16le(boot + 17);
        uint16_t tot16 = fg_rd16le(boot + 19);
        uint16_t spf = fg_rd16le(boot + 22);
        uint32_t tot32 = fg_rd32le(boot + 32);
        uint32_t tot = tot16 ? tot16 : tot32;
        if (bps && spc) {
            uint32_t root_sec = ((uint32_t)rde * 32 + bps - 1) / bps;
            uint32_t data = tot - (rsv + (uint32_t)boot[16] * spf + root_sec);
            uint32_t clusters = data / spc;
            if (clusters < 4085) return FG_FS_FAT12;
            return FG_FS_FAT16;
        }
        return FG_FS_FAT16;
    }
    /* ext2/3/4 superblock at byte 1024, magic 0xEF53 at sb+56 */
    if (n >= 1024 + 120 && fg_rd16le(boot + 1024 + 56) == 0xEF53) {
        uint32_t compat   = fg_rd32le(boot + 1024 + 92);
        uint32_t incompat = fg_rd32le(boot + 1024 + 96);
        if (label && labsz) {
            char lb[17];
            memcpy(lb, boot + 1024 + 120, 16);
            lb[16] = '\0';
            snprintf(label, labsz, "%s", lb);
        }
        if (incompat & 0x0040) return FG_FS_EXT4;     /* EXTENTS              */
        if (compat & 0x0004)   return FG_FS_EXT3;     /* HAS_JOURNAL          */
        return FG_FS_EXT2;
    }
    if (n >= 1024 + 2 && (!memcmp(boot + 1024, "H+", 2) || !memcmp(boot + 1024, "HX", 2)))
        return FG_FS_HFSPLUS;
    if (n >= 32 + 4 && !memcmp(boot + 32, "NXSB", 4)) return FG_FS_APFS;
    if (n >= 4 && !memcmp(boot, "XFSB", 4)) return FG_FS_XFS;
    if (n >= 0x10040 + 8 && !memcmp(boot + 0x10040, "_BHRfS_M", 8)) return FG_FS_BTRFS;
    return FG_FS_UNKNOWN;
}

/* -------------------------------------------------------------------------- */
static void probe_volume(fg_dev *d, fg_partition *p)
{
    uint8_t boot[4096];
    size_t got = 0;
    if (fg_dev_pread(d, boot, sizeof boot, p->start_bytes, &got) != FG_OK || got < 512)
        return;
    p->fs = fg_fs_identify(boot, got, p->fs_label, sizeof p->fs_label);
}

static fg_status read_gpt(fg_dev *d, uint32_t ss, fg_partition_table *out)
{
    uint8_t hdr[512], *ents;
    size_t got = 0;
    uint64_t ent_lba;
    uint32_t nent, entsz, i;

    if (fg_dev_pread(d, hdr, sizeof hdr, (uint64_t)ss, &got) != FG_OK || got < 92)
        return FG_ERR_IO;
    if (memcmp(hdr, "EFI PART", 8)) return FG_ERR_NOTFOUND;

    ent_lba = fg_rd64le(hdr + 72);
    nent    = fg_rd32le(hdr + 80);
    entsz   = fg_rd32le(hdr + 84);
    if (!nent || nent > 1024 || entsz < 128 || entsz > 1024) return FG_ERR_CORRUPT;

    ents = (uint8_t *)malloc((size_t)nent * entsz);
    if (!ents) return FG_ERR_NOMEM;
    if (fg_dev_pread(d, ents, (size_t)nent * entsz, ent_lba * ss, &got) != FG_OK) {
        free(ents);
        return FG_ERR_IO;
    }

    out->scheme = 2;
    out->sector_size = ss;
    for (i = 0; i < nent && out->count < FG_MAX_PARTS; i++) {
        const uint8_t *e = ents + (size_t)i * entsz;
        fg_partition *p;
        uint64_t first, last;
        int k, empty = 1;
        for (k = 0; k < 16; k++) if (e[k]) { empty = 0; break; }
        if (empty) continue;
        first = fg_rd64le(e + 32);
        last  = fg_rd64le(e + 40);
        if (last < first) continue;
        p = &out->parts[out->count];
        memset(p, 0, sizeof *p);
        p->index = out->count + 1;
        p->start_lba = first;
        p->sector_count = last - first + 1;
        p->start_bytes = first * ss;
        p->size_bytes = p->sector_count * ss;
        /* GUID as a readable type string (mixed-endian per the UEFI spec). */
        snprintf(p->gpt_type, sizeof p->gpt_type,
                 "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                 fg_rd32le(e), fg_rd16le(e + 4), fg_rd16le(e + 6),
                 e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15]);
        /* UTF-16LE partition name -> ASCII, good enough for a report. */
        for (k = 0; k < 35; k++) {
            uint16_t wc = fg_rd16le(e + 56 + k * 2);
            if (!wc) break;
            p->label[k] = (wc < 0x80) ? (char)wc : '?';
        }
        probe_volume(d, p);
        out->count++;
    }
    free(ents);
    return FG_OK;
}

static void read_ebr_chain(fg_dev *d, uint32_t ss, uint64_t ext_base,
                           uint64_t cur, fg_partition_table *out, int depth)
{
    uint8_t sec[512];
    size_t got = 0;
    int i;
    if (depth > 32 || out->count >= FG_MAX_PARTS) return;
    if (fg_dev_pread(d, sec, sizeof sec, cur * ss, &got) != FG_OK || got < 512) return;
    if (fg_rd16le(sec + 510) != 0xAA55) return;

    for (i = 0; i < 2; i++) {
        const uint8_t *e = sec + 446 + i * 16;
        uint8_t type = e[4];
        uint32_t rel = fg_rd32le(e + 8), cnt = fg_rd32le(e + 12);
        if (!type || !cnt) continue;
        if (type == 0x05 || type == 0x0F || type == 0x85) {
            read_ebr_chain(d, ss, ext_base, ext_base + rel, out, depth + 1);
        } else if (out->count < FG_MAX_PARTS) {
            fg_partition *p = &out->parts[out->count];
            memset(p, 0, sizeof *p);
            p->index = out->count + 1;
            p->mbr_type = type;
            p->start_lba = cur + rel;
            p->sector_count = cnt;
            p->start_bytes = p->start_lba * ss;
            p->size_bytes = (uint64_t)cnt * ss;
            snprintf(p->label, sizeof p->label, "logical (type 0x%02X)", type);
            probe_volume(d, p);
            out->count++;
        }
    }
}

fg_status fg_parts_read(fg_dev *d, fg_partition_table *out)
{
    uint8_t mbr[512];
    size_t got = 0;
    uint32_t ss;
    int i, protective = 0;

    if (!d || !out) return FG_ERR_INVALID;
    memset(out, 0, sizeof *out);
    ss = fg_dev_sector(d);
    if (!ss) ss = 512;
    out->sector_size = ss;

    if (fg_dev_pread(d, mbr, sizeof mbr, 0, &got) != FG_OK || got < 512)
        return FG_ERR_IO;
    if (fg_rd16le(mbr + 510) != 0xAA55) return FG_ERR_NOTFOUND;

    for (i = 0; i < 4; i++)
        if (mbr[446 + i * 16 + 4] == 0xEE) protective = 1;

    if (protective && read_gpt(d, ss, out) == FG_OK && out->count) return FG_OK;

    out->scheme = 1;
    for (i = 0; i < 4; i++) {
        const uint8_t *e = mbr + 446 + i * 16;
        uint8_t type = e[4];
        uint32_t lba = fg_rd32le(e + 8), cnt = fg_rd32le(e + 12);
        if (!type || !cnt) continue;
        if (type == 0x05 || type == 0x0F || type == 0x85) {
            read_ebr_chain(d, ss, lba, lba, out, 0);
            continue;
        }
        if (out->count >= FG_MAX_PARTS) break;
        {
            fg_partition *p = &out->parts[out->count];
            memset(p, 0, sizeof *p);
            p->index = out->count + 1;
            p->mbr_type = type;
            p->bootable = (e[0] == 0x80);
            p->start_lba = lba;
            p->sector_count = cnt;
            p->start_bytes = (uint64_t)lba * ss;
            p->size_bytes = (uint64_t)cnt * ss;
            snprintf(p->label, sizeof p->label, "primary (type 0x%02X)", type);
            probe_volume(d, p);
            out->count++;
        }
    }
    return out->count ? FG_OK : FG_ERR_NOTFOUND;
}

/* -------------------------------------------------------------------------- */
/*  allocation bitmaps                                                        */
/* -------------------------------------------------------------------------- */
int fg_alloc_map_is_allocated(const fg_alloc_map *m, uint64_t byte_off)
{
    uint64_t c;
    if (!m || !m->valid || byte_off < m->data_start) return 0;
    c = (byte_off - m->data_start) / m->cluster_size;
    if (c >= m->cluster_count) return 0;
    return (m->bits[c >> 3] >> (c & 7)) & 1;
}

void fg_alloc_map_free(fg_alloc_map *m)
{
    if (!m) return;
    free(m->bits);
    m->bits = NULL;
    m->valid = 0;
}
