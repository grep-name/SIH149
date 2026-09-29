
#include "fs_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define A_STANDARD_INFO 0x10
#define A_FILE_NAME     0x30
#define A_DATA          0x80
#define A_BITMAP        0xB0

typedef struct {
    uint32_t bytes_per_sector;
    uint32_t cluster_size;
    uint64_t total_sectors;
    uint64_t mft_lcn;
    uint32_t mft_record_size;
    uint64_t vol_off;
} ntfs_vol;

/* ---- boot sector --------------------------------------------------------- */
static int ntfs_read_boot(fg_fs_ctx *c, ntfs_vol *v)
{
    uint8_t b[512];
    size_t got = 0;
    int8_t cpr;
    uint8_t spc;

    if (fg_dev_pread(c->dev, b, sizeof b, c->vol_off, &got) != FG_OK || got < 512)
        return 0;
    if (memcmp(b + 3, "NTFS    ", 8)) return 0;

    v->bytes_per_sector = fg_rd16le(b + 11);
    spc = b[13];
    if (!v->bytes_per_sector || v->bytes_per_sector & (v->bytes_per_sector - 1)) return 0;
    /* sectors_per_cluster is a power-of-two exponent when >= 0x80 */
    v->cluster_size = (spc >= 0x80) ? (uint32_t)(1u << (256 - spc)) * v->bytes_per_sector
                                    : (uint32_t)spc * v->bytes_per_sector;
    if (!v->cluster_size || v->cluster_size > 2u * 1024u * 1024u) return 0;

    v->total_sectors = fg_rd64le(b + 0x28);
    v->mft_lcn       = fg_rd64le(b + 0x30);
    cpr              = (int8_t)b[0x40];
    v->mft_record_size = (cpr < 0) ? (uint32_t)(1u << (unsigned)(-cpr))
                                   : (uint32_t)cpr * v->cluster_size;
    if (v->mft_record_size < 256 || v->mft_record_size > 65536) v->mft_record_size = 1024;
    v->vol_off = c->vol_off;
    return 1;
}

/* ---- fixups -------------------------------------------------------------- */
/* Every sector of an MFT record ends with two bytes stolen for the update
 * sequence; without putting them back the record is subtly corrupt. */
static int ntfs_fixup(uint8_t *rec, uint32_t size, uint32_t sector)
{
    uint16_t usa_off = fg_rd16le(rec + 4);
    uint16_t usa_cnt = fg_rd16le(rec + 6);
    uint16_t seq;
    uint16_t i;
    if (!usa_cnt || usa_off + usa_cnt * 2u > size) return 0;
    seq = fg_rd16le(rec + usa_off);
    for (i = 1; i < usa_cnt; i++) {
        uint32_t tail = i * sector - 2;
        if (tail + 2 > size) return 0;
        if (fg_rd16le(rec + tail) != seq) return 0;    /* torn write          */
        rec[tail]     = rec[usa_off + i * 2];
        rec[tail + 1] = rec[usa_off + i * 2 + 1];
    }
    return 1;
}

/* ---- run lists ----------------------------------------------------------- */
/* Decode NTFS mapping pairs into absolute device extents. Sparse runs (offset
 * field of length zero) are represented as holes and skipped. */
static int ntfs_decode_runs(const uint8_t *p, size_t avail, const ntfs_vol *v,
                            uint64_t data_size, fg_run *out, int maxruns)
{
    int n = 0;
    int64_t lcn = 0;
    uint64_t remaining = data_size;
    size_t i = 0;

    while (i < avail && p[i] && n < maxruns && remaining) {
        uint8_t hdr = p[i++];
        int lsz = hdr & 0x0F, osz = (hdr >> 4) & 0x0F;
        uint64_t rlen = 0;
        int64_t roff = 0;
        int k;
        if (!lsz || i + lsz + osz > avail) break;
        for (k = 0; k < lsz; k++) rlen |= (uint64_t)p[i + k] << (8 * k);
        i += lsz;
        if (osz) {
            for (k = 0; k < osz; k++) roff |= (int64_t)p[i + k] << (8 * k);
            /* sign-extend */
            if (p[i + osz - 1] & 0x80) roff |= -((int64_t)1 << (8 * osz));
            i += osz;
            lcn += roff;
            if (lcn < 0) break;
            {
                uint64_t bytes = rlen * v->cluster_size;
                if (bytes > remaining) bytes = remaining;
                out[n].off = v->vol_off + (uint64_t)lcn * v->cluster_size;
                out[n].len = bytes;
                remaining -= bytes;
                n++;
            }
        } else {
            /* sparse run: contributes zeros, so just consume the length */
            uint64_t bytes = rlen * v->cluster_size;
            if (bytes > remaining) bytes = remaining;
            remaining -= bytes;
            i += 0;
        }
    }
    return n;
}

/* ---- attribute walking --------------------------------------------------- */
typedef struct {
    const uint8_t *val;      /* resident value                                */
    uint32_t       vallen;
    const uint8_t *runs;     /* mapping pairs for non-resident                */
    size_t         runs_avail;
    uint64_t       data_size;
    int            non_resident;
    int            found;
} ntfs_attr;

static void ntfs_find_attr(const uint8_t *rec, uint32_t used, uint32_t type,
                           int unnamed_only, ntfs_attr *out)
{
    uint32_t off = fg_rd16le(rec + 0x14);
    memset(out, 0, sizeof *out);
    while (off + 8 <= used) {
        uint32_t atype = fg_rd32le(rec + off);
        uint32_t alen;
        if (atype == 0xFFFFFFFFu) break;
        alen = fg_rd32le(rec + off + 4);
        if (alen < 16 || off + alen > used) break;
        if (atype == type) {
            uint8_t namelen = rec[off + 9];
            if (!unnamed_only || !namelen) {
                if (!rec[off + 8]) {              /* resident                 */
                    uint32_t vlen = fg_rd32le(rec + off + 0x10);
                    uint16_t voff = fg_rd16le(rec + off + 0x14);
                    if (voff < alen && (uint64_t)off + voff + vlen <= used) {
                        out->val = rec + off + voff;
                        out->vallen = vlen;
                        out->data_size = vlen;
                        out->non_resident = 0;
                        out->found = 1;
                        return;
                    }
                } else {                          /* non-resident             */
                    uint16_t mpoff = fg_rd16le(rec + off + 0x20);
                    if (mpoff < alen) {
                        out->runs = rec + off + mpoff;
                        out->runs_avail = alen - mpoff;
                        out->data_size = fg_rd64le(rec + off + 0x30);
                        out->non_resident = 1;
                        out->found = 1;
                        return;
                    }
                }
            }
        }
        off += alen;
    }
}

/* Pick the best $FILE_NAME: prefer Win32 (namespace 1) or Win32+DOS (3) over
 * the 8.3 short name (2). */
static void ntfs_best_name(const uint8_t *rec, uint32_t used,
                           char *out, size_t outsz, int64_t *mtime)
{
    uint32_t off = fg_rd16le(rec + 0x14);
    int best_ns = -1;
    out[0] = '\0';
    if (mtime) *mtime = 0;
    while (off + 8 <= used) {
        uint32_t atype = fg_rd32le(rec + off);
        uint32_t alen;
        if (atype == 0xFFFFFFFFu) break;
        alen = fg_rd32le(rec + off + 4);
        if (alen < 16 || off + alen > used) break;
        if (atype == A_FILE_NAME && !rec[off + 8]) {
            uint16_t voff = fg_rd16le(rec + off + 0x14);
            const uint8_t *fn = rec + off + voff;
            uint32_t vlen = fg_rd32le(rec + off + 0x10);
            if (vlen >= 0x42 && off + voff + vlen <= used) {
                uint8_t nlen = fn[0x40], ns = fn[0x41];
                int rank = (ns == 1 || ns == 3) ? 3 : (ns == 0 ? 2 : 1);
                if (rank > best_ns && (uint32_t)0x42 + nlen * 2u <= vlen) {
                    best_ns = rank;
                    fg_utf16le_to_utf8(fn + 0x42, nlen, out, outsz);
                    if (mtime) *mtime = fg_filetime_to_unix(fg_rd64le(fn + 0x10));
                }
            }
        }
        off += alen;
    }
}

/* ---- reading $MFT itself ------------------------------------------------- */
/* $MFT is a file like any other and is usually fragmented, so record 0 is read
 * directly from the boot-sector LCN and its own run list drives the rest. */
static int ntfs_mft_runs(fg_fs_ctx *c, const ntfs_vol *v, fg_run *runs, int maxruns)
{
    uint8_t *rec = (uint8_t *)malloc(v->mft_record_size);
    size_t got = 0;
    int n = 0;
    ntfs_attr a;
    if (!rec) return 0;
    if (fg_dev_pread(c->dev, rec, v->mft_record_size,
                     v->vol_off + v->mft_lcn * v->cluster_size, &got) != FG_OK ||
        got < v->mft_record_size || memcmp(rec, "FILE", 4)) {
        free(rec);
        return 0;
    }
    ntfs_fixup(rec, v->mft_record_size, v->bytes_per_sector);
    {
        uint32_t used = fg_rd32le(rec + 0x18);
        if (used > v->mft_record_size) used = v->mft_record_size;
        ntfs_find_attr(rec, used, A_DATA, 1, &a);
        if (a.found && a.non_resident)
            n = ntfs_decode_runs(a.runs, a.runs_avail, v, a.data_size, runs, maxruns);
    }
    free(rec);
    return n;
}

fg_status fg_ntfs_recover(fg_fs_ctx *c)
{
    ntfs_vol v;
    fg_run mft_runs[256];
    int nmft, ri;
    uint8_t *rec;
    uint64_t scanned = 0, total_records = 0;
    fg_run runs[256];

    if (!ntfs_read_boot(c, &v)) return FG_ERR_NOTFOUND;
    c->cluster_size = v.cluster_size;

    nmft = ntfs_mft_runs(c, &v, mft_runs, (int)FG_ARRAY_LEN(mft_runs));
    if (!nmft) {
        /* Fall back to a contiguous $MFT starting at the boot-sector LCN. */
        mft_runs[0].off = v.vol_off + v.mft_lcn * v.cluster_size;
        mft_runs[0].len = FG_MIN(c->vol_size ? c->vol_size : (uint64_t)1 << 30,
                                 (uint64_t)1 << 30);
        nmft = 1;
    }
    for (ri = 0; ri < nmft; ri++) total_records += mft_runs[ri].len / v.mft_record_size;

    rec = (uint8_t *)malloc(v.mft_record_size);
    if (!rec) return FG_ERR_NOMEM;

    for (ri = 0; ri < nmft; ri++) {
        uint64_t pos = 0;
        while (pos + v.mft_record_size <= mft_runs[ri].len) {
            size_t got = 0;
            uint32_t used, flags;
            char name[512];
            int64_t mtime = 0;
            ntfs_attr data;

            if (fg_dev_pread(c->dev, rec, v.mft_record_size,
                             mft_runs[ri].off + pos, &got) != FG_OK ||
                got < v.mft_record_size) break;
            pos += v.mft_record_size;
            scanned++;
            if ((scanned & 1023) == 0 &&
                fg_progress_report(&c->opts->progress, "ntfs-mft",
                                   scanned, total_records, NULL))
                break;

            if (memcmp(rec, "FILE", 4)) continue;
            if (!ntfs_fixup(rec, v.mft_record_size, v.bytes_per_sector)) continue;

            flags = fg_rd16le(rec + 0x16);
            if (flags & 0x0002) continue;                 /* directory        */
            if (flags & 0x0001) continue;                 /* still in use     */
            /* An extension record has a non-zero base reference; its data is
             * described by the base record, so skip it here. */
            if (fg_rd64le(rec + 0x20) & 0x0000FFFFFFFFFFFFull) continue;

            used = fg_rd32le(rec + 0x18);
            if (used < 0x30 || used > v.mft_record_size) continue;

            ntfs_best_name(rec, used, name, sizeof name, &mtime);
            if (!name[0]) snprintf(name, sizeof name, "mft_%llu.bin",
                                   (unsigned long long)scanned);

            ntfs_find_attr(rec, used, A_DATA, 1, &data);
            if (!data.found || !data.data_size) continue;

            if (!data.non_resident) {
                /* Small files live entirely inside the record - these survive
                 * a delete completely intact. */
                fg_fs_emit(c, name, FG_FS_NTFS, NULL, 0, data.val,
                           FG_MIN(data.data_size, (uint64_t)data.vallen),
                           mtime, 1, 0);
            } else {
                int nr = ntfs_decode_runs(data.runs, data.runs_avail, &v,
                                          data.data_size, runs,
                                          (int)FG_ARRAY_LEN(runs));
                if (nr > 0)
                    fg_fs_emit(c, name, FG_FS_NTFS, runs, nr, NULL,
                               data.data_size, mtime, 1, nr > 1);
            }
        }
    }
    free(rec);
    return FG_OK;
}

/* ---- $Bitmap ------------------------------------------------------------- */
fg_status fg_ntfs_load_bitmap(fg_fs_ctx *c, fg_alloc_map *m)
{
    ntfs_vol v;
    fg_run mft_runs[64];
    uint8_t *rec;
    int nmft, i;
    fg_status st = FG_ERR_NOTFOUND;

    memset(m, 0, sizeof *m);
    if (!ntfs_read_boot(c, &v)) return FG_ERR_NOTFOUND;
    nmft = ntfs_mft_runs(c, &v, mft_runs, (int)FG_ARRAY_LEN(mft_runs));
    if (!nmft) return FG_ERR_NOTFOUND;

    rec = (uint8_t *)malloc(v.mft_record_size);
    if (!rec) return FG_ERR_NOMEM;

    /* $Bitmap is MFT record 6. */
    {
        uint64_t want = 6ull * v.mft_record_size, pos = 0, off = 0;
        size_t got = 0;
        for (i = 0; i < nmft; i++) {
            if (pos + mft_runs[i].len > want) { off = mft_runs[i].off + (want - pos); break; }
            pos += mft_runs[i].len;
        }
        if (!off) { free(rec); return FG_ERR_NOTFOUND; }
        if (fg_dev_pread(c->dev, rec, v.mft_record_size, off, &got) == FG_OK &&
            got == v.mft_record_size && !memcmp(rec, "FILE", 4)) {
            ntfs_attr a;
            uint32_t used;
            ntfs_fixup(rec, v.mft_record_size, v.bytes_per_sector);
            used = fg_rd32le(rec + 0x18);
            if (used > v.mft_record_size) used = v.mft_record_size;
            ntfs_find_attr(rec, used, A_DATA, 1, &a);
            if (a.found && a.non_resident && a.data_size &&
                a.data_size < 256ull * 1024 * 1024) {
                fg_run br[128];
                int nb = ntfs_decode_runs(a.runs, a.runs_avail, &v, a.data_size,
                                          br, (int)FG_ARRAY_LEN(br));
                if (nb > 0) {
                    uint8_t *bits = (uint8_t *)malloc((size_t)a.data_size);
                    uint64_t filled = 0;
                    int k;
                    if (bits) {
                        for (k = 0; k < nb && filled < a.data_size; k++) {
                            size_t g = 0;
                            fg_dev_pread(c->dev, bits + filled, (size_t)br[k].len,
                                         br[k].off, &g);
                            filled += g;
                        }
                        m->bits = bits;
                        m->cluster_size = v.cluster_size;
                        m->cluster_count = filled * 8;
                        m->data_start = v.vol_off;
                        m->valid = 1;
                        st = FG_OK;
                    }
                }
            }
        }
    }
    free(rec);
    return st;
}
