
#include "fs_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    uint32_t block_size;
    uint32_t inodes_per_group;
    uint32_t blocks_per_group;
    uint32_t inode_size;
    uint32_t inode_count;
    uint32_t block_count;
    uint32_t first_data_block;
    uint32_t desc_size;
    int      is64;
    int      extents;
    fg_fs_kind kind;
} ext_vol;

static int ext_read_sb(fg_fs_ctx *c, ext_vol *v)
{
    uint8_t sb[1024];
    size_t got = 0;
    uint32_t feat_incompat, feat_ro;

    if (fg_dev_pread(c->dev, sb, sizeof sb, c->vol_off + 1024, &got) != FG_OK ||
        got < 1024) return 0;
    if (fg_rd16le(sb + 56) != 0xEF53) return 0;

    memset(v, 0, sizeof *v);
    v->block_size       = 1024u << fg_rd32le(sb + 24);
    v->blocks_per_group = fg_rd32le(sb + 32);
    v->inodes_per_group = fg_rd32le(sb + 40);
    v->inode_count      = fg_rd32le(sb + 0);
    v->block_count      = fg_rd32le(sb + 4);
    v->first_data_block = fg_rd32le(sb + 20);
    v->inode_size       = fg_rd16le(sb + 88);
    if (v->inode_size < 128) v->inode_size = 128;
    feat_incompat = fg_rd32le(sb + 96);
    feat_ro       = fg_rd32le(sb + 100);
    v->extents = (feat_incompat & 0x0040) ? 1 : 0;
    v->is64    = (feat_incompat & 0x0080) ? 1 : 0;
    v->desc_size = v->is64 ? fg_rd16le(sb + 254) : 32;
    if (v->desc_size < 32) v->desc_size = 32;
    v->kind = v->extents ? FG_FS_EXT4
            : ((fg_rd32le(sb + 92) & 0x0004) ? FG_FS_EXT3 : FG_FS_EXT2);
    FG_UNUSED(feat_ro);
    if (!v->block_size || !v->blocks_per_group || !v->inodes_per_group) return 0;
    return 1;
}

static uint64_t ext_inode_offset(fg_fs_ctx *c, const ext_vol *v, uint32_t ino)
{
    uint32_t group, idx;
    uint64_t gd_block, gd_off, table;
    uint8_t gd[64];
    size_t got = 0;
    if (ino < 1) return 0;
    group = (ino - 1) / v->inodes_per_group;
    idx   = (ino - 1) % v->inodes_per_group;
    gd_block = v->first_data_block + 1;
    gd_off = c->vol_off + gd_block * (uint64_t)v->block_size +
             (uint64_t)group * v->desc_size;
    if (fg_dev_pread(c->dev, gd, FG_MIN(v->desc_size, (uint32_t)sizeof gd),
                     gd_off, &got) != FG_OK || got < 32) return 0;
    table = fg_rd32le(gd + 8);
    if (v->is64 && v->desc_size >= 40) table |= (uint64_t)fg_rd32le(gd + 40) << 32;
    if (!table) return 0;
    return c->vol_off + table * v->block_size + (uint64_t)idx * v->inode_size;
}


static int ext_extents(fg_fs_ctx *c, const ext_vol *v, const uint8_t *iblock,
                       uint64_t size, fg_run *runs, int maxruns, int depth)
{
    uint16_t magic = fg_rd16le(iblock);
    uint16_t entries = fg_rd16le(iblock + 2);
    uint16_t dep = fg_rd16le(iblock + 6);
    int n = 0, i;
    uint64_t remaining = size;

    if (magic != 0xF30A || depth > 5) return 0;
    for (i = 0; i < entries && n < maxruns && remaining; i++) {
        const uint8_t *e = iblock + 12 + i * 12;
        if (dep == 0) {
            uint16_t len = fg_rd16le(e + 4);
            uint64_t start = fg_rd32le(e + 8) | ((uint64_t)fg_rd16le(e + 6) << 32);
            uint64_t bytes;
            if (len > 32768) len = (uint16_t)(len - 32768);   /* uninitialised */
            bytes = (uint64_t)len * v->block_size;
            if (bytes > remaining) bytes = remaining;
            if (!start) continue;
            runs[n].off = c->vol_off + start * v->block_size;
            runs[n].len = bytes;
            remaining -= bytes;
            n++;
        } else {
            uint64_t leaf = fg_rd32le(e + 4) | ((uint64_t)fg_rd16le(e + 8) << 32);
            uint8_t *blk = (uint8_t *)malloc(v->block_size);
            size_t got = 0;
            if (!blk) break;
            if (fg_dev_pread(c->dev, blk, v->block_size,
                             c->vol_off + leaf * v->block_size, &got) == FG_OK &&
                got >= 12) {
                int sub = ext_extents(c, v, blk, remaining, runs + n, maxruns - n,
                                      depth + 1);
                int k;
                for (k = 0; k < sub; k++) remaining -= FG_MIN(remaining, runs[n + k].len);
                n += sub;
            }
            free(blk);
        }
    }
    return n;
}


static int ext_blockmap(fg_fs_ctx *c, const ext_vol *v, const uint8_t *iblock,
                        uint64_t size, fg_run *runs, int maxruns)
{
    int n = 0, i;
    uint64_t remaining = size;
    uint32_t ppb = v->block_size / 4;

    for (i = 0; i < 12 && remaining && n < maxruns; i++) {
        uint32_t b = fg_rd32le(iblock + i * 4);
        uint64_t bytes;
        if (!b) continue;
        bytes = FG_MIN((uint64_t)v->block_size, remaining);
        /* Coalesce consecutive direct blocks so the run list stays short. */
        if (n && runs[n-1].off + runs[n-1].len == c->vol_off + (uint64_t)b * v->block_size) {
            runs[n-1].len += bytes;
        } else {
            runs[n].off = c->vol_off + (uint64_t)b * v->block_size;
            runs[n].len = bytes;
            n++;
        }
        remaining -= bytes;
    }

    if (remaining && n < maxruns) {
        uint32_t ind = fg_rd32le(iblock + 12 * 4);
        if (ind) {
            uint8_t *blk = (uint8_t *)malloc(v->block_size);
            size_t got = 0;
            if (blk && fg_dev_pread(c->dev, blk, v->block_size,
                                    c->vol_off + (uint64_t)ind * v->block_size,
                                    &got) == FG_OK) {
                uint32_t k;
                for (k = 0; k < ppb && remaining && n < maxruns; k++) {
                    uint32_t b = fg_rd32le(blk + k * 4);
                    uint64_t bytes;
                    if (!b) continue;
                    bytes = FG_MIN((uint64_t)v->block_size, remaining);
                    if (n && runs[n-1].off + runs[n-1].len ==
                             c->vol_off + (uint64_t)b * v->block_size) {
                        runs[n-1].len += bytes;
                    } else {
                        runs[n].off = c->vol_off + (uint64_t)b * v->block_size;
                        runs[n].len = bytes;
                        n++;
                    }
                    remaining -= bytes;
                }
            }
            free(blk);
        }
    }
    return n;
}


typedef struct { uint32_t ino; char name[256]; } orphan;

static int ext_scan_dirblock(const uint8_t *blk, uint32_t bs,
                             orphan *out, int maxout)
{
    uint32_t off = 0;
    int n = 0;
    while (off + 8 < bs && n < maxout) {
        uint32_t ino = fg_rd32le(blk + off);
        uint16_t rec = fg_rd16le(blk + off + 4);
        uint8_t nlen = blk[off + 6];
        uint32_t used;
        if (rec < 8 || rec > bs - off || (rec & 3)) break;
        used = 8u + nlen;
        used = (used + 3u) & ~3u;

        {
            uint32_t g = off + used;
            while (g + 8 < off + rec && n < maxout) {
                uint32_t gino = fg_rd32le(blk + g);
                uint16_t grec = fg_rd16le(blk + g + 4);
                uint8_t  gnl  = blk[g + 6];
                if (gino && gino < 0x10000000u && gnl && gnl < 200 &&
                    g + 8u + gnl <= bs && grec >= 8) {
                    out[n].ino = gino;
                    memcpy(out[n].name, blk + g + 8, gnl);
                    out[n].name[gnl] = '\0';
                    n++;
                }
                if (grec < 8 || (grec & 3)) break;
                g += grec;
            }
        }
        if (ino && nlen && off + 8u + nlen <= bs) {
 
        }
        off += rec;
    }
    return n;
}

fg_status fg_ext_recover(fg_fs_ctx *c)
{
    ext_vol v;
    uint32_t ino;
    uint8_t *inode;
    uint64_t recovered = 0;
    orphan *orphans;
    int norph = 0, maxorph = 4096;

    if (!ext_read_sb(c, &v)) return FG_ERR_NOTFOUND;
    c->cluster_size = v.block_size;

    inode = (uint8_t *)malloc(v.inode_size);
    orphans = (orphan *)fg_xcalloc((size_t)maxorph, sizeof *orphans);
    if (!inode || !orphans) { free(inode); free(orphans); return FG_ERR_NOMEM; }

    /* Collect orphaned names from the root directory first so recovered
     * inodes can be given their real filenames. */
    {
        uint64_t root_off = ext_inode_offset(c, &v, 2);
        size_t got = 0;
        if (root_off && fg_dev_pread(c->dev, inode, v.inode_size, root_off, &got) == FG_OK &&
            got >= 128) {
            fg_run runs[64];
            int nr, i;
            uint64_t sz = fg_rd32le(inode + 4);
            uint32_t iflags = fg_rd32le(inode + 32);
            if (iflags & 0x80000) nr = ext_extents(c, &v, inode + 40, sz, runs, 64, 0);
            else                  nr = ext_blockmap(c, &v, inode + 40, sz, runs, 64);
            for (i = 0; i < nr && norph < maxorph; i++) {
                uint8_t *blk = (uint8_t *)malloc(v.block_size);
                uint64_t o = 0;
                if (!blk) break;
                while (o < runs[i].len && norph < maxorph) {
                    size_t g = 0;
                    if (fg_dev_pread(c->dev, blk, v.block_size, runs[i].off + o, &g) != FG_OK)
                        break;
                    norph += ext_scan_dirblock(blk, v.block_size,
                                               orphans + norph, maxorph - norph);
                    o += v.block_size;
                }
                free(blk);
            }
        }
    }

    /* Walk the inode table looking for deleted-but-intact inodes: a non-zero
     * deletion time with a size and a link count of zero. */
    for (ino = 11; ino <= v.inode_count && ino < 2000000u; ino++) {
        uint64_t ioff = ext_inode_offset(c, &v, ino);
        size_t got = 0;
        uint16_t links;
        uint32_t dtime, mode;
        uint64_t size;
        fg_run runs[128];
        int nr = 0, k;
        char name[256];

        if (!ioff) break;
        if (fg_dev_pread(c->dev, inode, v.inode_size, ioff, &got) != FG_OK || got < 128)
            break;
        mode  = fg_rd16le(inode + 0);
        links = fg_rd16le(inode + 26);
        dtime = fg_rd32le(inode + 20);
        size  = fg_rd32le(inode + 4) | ((uint64_t)fg_rd32le(inode + 108) << 32);

        if (!dtime || links) continue;               /* not a deleted file    */
        if ((mode & 0xF000) != 0x8000) continue;     /* regular files only    */
        if (!size || size > 512ull * 1024 * 1024) continue;

        if (fg_rd32le(inode + 32) & 0x80000)
            nr = ext_extents(c, &v, inode + 40, size, runs, (int)FG_ARRAY_LEN(runs), 0);
        else
            nr = ext_blockmap(c, &v, inode + 40, size, runs, (int)FG_ARRAY_LEN(runs));
        if (nr <= 0) continue;   /* ext3/4 zeroed the pointers: carving only  */

        name[0] = '\0';
        for (k = 0; k < norph; k++)
            if (orphans[k].ino == ino) { snprintf(name, sizeof name, "%s", orphans[k].name); break; }
        if (!name[0]) snprintf(name, sizeof name, "inode_%u.bin", ino);

        fg_fs_emit(c, name, v.kind, runs, nr, NULL, size,
                   (int64_t)fg_rd32le(inode + 16), 1, nr > 1);
        recovered++;
        if ((ino & 4095) == 0 &&
            fg_progress_report(&c->opts->progress, "ext-inodes", ino, v.inode_count, NULL))
            break;
    }

    free(inode);
    free(orphans);
    return FG_OK;
}
