#include "forge/fg_carve.h"
#include "forge/fg_fs.h"
#include "forge/fg_crypto.h"
#include "forge/fg_audit.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define SCAN_BLOCK   (8u * 1024u * 1024u)
#define WINDOW_CAP   (48u * 1024u * 1024u)
#define PROBE_SIZE   (64u * 1024u)
#define GROW_SIZE    (4u * 1024u * 1024u)
#define MAX_HITS     (4u * 1024u * 1024u)

void fg_scan_opts_default(fg_scan_opts *o)
{
    memset(o, 0, sizeof *o);
    o->block_size     = SCAN_BLOCK;
    o->do_metadata    = 1;
    o->do_carve       = 1;
    o->do_fragment    = 1;
    o->min_confidence = 30;
    o->max_file_size  = 2ull * 1024 * 1024 * 1024;
    o->write_files    = 1;
    o->preserve_names = 1;
}


typedef struct { uint64_t off; int32_t sig; } hit;

typedef struct {
    hit     *v;
    uint64_t n, cap;
    uint64_t dropped;
} hitlist;

static void hit_add(void *user, uint64_t off, int sig_index)
{
    hitlist *h = (hitlist *)user;
    if (h->n == h->cap) {
        uint64_t ncap = h->cap ? h->cap * 2 : 4096;
        hit *nv;
        if (ncap > MAX_HITS) { h->dropped++; return; }
        nv = (hit *)realloc(h->v, (size_t)ncap * sizeof *nv);
        if (!nv) { h->dropped++; return; }
        h->v = nv;
        h->cap = ncap;
    }
    h->v[h->n].off = off;
    h->v[h->n].sig = sig_index;
    h->n++;
}

static int hit_cmp(const void *a, const void *b)
{
    const hit *x = (const hit *)a, *y = (const hit *)b;
    if (x->off < y->off) return -1;
    if (x->off > y->off) return 1;
    return x->sig - y->sig;
}


static int in_csv(const char *csv, const char *word)
{
    const char *p = csv;
    size_t wl = strlen(word);
    if (!csv || !*csv) return 1;
    while (*p) {
        const char *c = strchr(p, ',');
        size_t len = c ? (size_t)(c - p) : strlen(p);
        while (len && (*p == ' ')) { p++; len--; }
        if (len == wl && fg_strcaseeq(word, p) == 0) {

        }
        if (len == wl) {
            size_t i;
            int eq = 1;
            for (i = 0; i < wl; i++) {
                int a = p[i], b = word[i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { eq = 0; break; }
            }
            if (eq) return 1;
        }
        if (!c) break;
        p = c + 1;
    }
    return 0;
}

static int *build_enabled(const fg_sig *sigs, int nsigs, const fg_scan_opts *o)
{
    int *en = (int *)fg_xcalloc((size_t)nsigs, sizeof *en);
    int i;
    if (!en) return NULL;
    for (i = 0; i < nsigs; i++) {
        int ok = 1;
        if (o->types && *o->types)      ok = in_csv(o->types, sigs[i].ext);
        if (ok && o->categories && *o->categories)
            ok = in_csv(o->categories, fg_category_name(sigs[i].category));
        en[i] = ok;
    }
    return en;
}


static uint64_t find_footer(const uint8_t *buf, size_t n, const fg_sig *s,
                            uint64_t min_size)
{
    size_t i;
    if (!s->footer || !s->footer_len) return 0;
    if (n < s->footer_len) return 0;
    for (i = (size_t)FG_MAX(min_size, (uint64_t)1); i + s->footer_len <= n; i++) {
        if (buf[i] == s->footer[0] && !memcmp(buf + i, s->footer, s->footer_len))
            return (uint64_t)i + (s->footer_inclusive ? s->footer_len : 0);
    }
    return 0;
}

static uint64_t gap_carve(const uint8_t *win, size_t wn, const fg_sig *s,
                          uint32_t cluster, int *quality,
                          uint64_t *frag_off, uint64_t *frag_len, int *nfrag)
{
    uint32_t cl = cluster ? cluster : 4096;
    uint64_t head, gap;
    uint8_t *tmp;
    uint64_t best = 0;
    int best_q = 0;

    if (!s->validate || wn < (size_t)cl * 4) return 0;
    tmp = (uint8_t *)malloc(wn);
    if (!tmp) return 0;

    for (head = cl; head <= (uint64_t)wn / 2 && head <= (uint64_t)cl * 24; head += cl) {
        for (gap = cl; gap <= (uint64_t)cl * 24; gap += cl) {
            uint64_t tail_src = head + gap, tail_len, len;
            int q = 0;
            if (tail_src >= (uint64_t)wn) break;
            tail_len = (uint64_t)wn - tail_src;
            memcpy(tmp, win, (size_t)head);
            memcpy(tmp + head, win + tail_src, (size_t)tail_len);
            len = s->validate(tmp, (size_t)(head + tail_len), s, &q);
            if (len && len != FG_LEN_UNKNOWN && len > head && q >= 2) {
                if (q > best_q) {
                    best_q = q;
                    best = len;
                    frag_off[0] = 0;          frag_len[0] = head;
                    frag_off[1] = tail_src;   frag_len[1] = len - head;
                    *nfrag = 2;
                    if (q >= 3) goto done;
                }
            }
        }
    }
done:
    free(tmp);
    if (best) *quality = best_q;
    return best;
}


static fg_status write_out(const char *dir, const char *name,
                           const uint8_t *data, uint64_t len, char *out_path,
                           size_t opsz)
{
    FILE *f;
    snprintf(out_path, opsz, "%s%c%s", dir, FG_PATH_SEP, name);
    f = fopen(out_path, "wb");
    if (!f) return FG_ERR_IO;
    if (len && fwrite(data, 1, (size_t)len, f) != (size_t)len) {
        fclose(f);
        return FG_ERR_IO;
    }
    fclose(f);
    return FG_OK;
}

static void hash_and_score(fg_recovered *r, const uint8_t *data, uint64_t len,
                           const fg_sig *sig)
{
    uint8_t d[32], m[16];
    fg_sha256 sh;
    fg_md5 md;
    fg_sha256_init(&sh);
    fg_md5_init(&md);
    fg_sha256_update(&sh, data, (size_t)len);
    fg_md5_update(&md, data, (size_t)len);
    fg_sha256_final(&sh, d);
    fg_md5_final(&md, m);
    fg_hex_encode(d, 32, r->sha256);
    fg_hex_encode(m, 16, r->md5);
    r->category = fg_classify(data, (size_t)len, sig);
    fg_confidence_score(r, data, (size_t)len, sig);
}


fg_status fg_carve_run(const char *source_path, const fg_scan_opts *o,
                       fg_scan_result *res)
{
    fg_dev *dev = NULL;
    const fg_sig *sigs;
    int nsigs, *enabled = NULL;
    fg_ac *ac = NULL;
    hitlist hl;
    uint8_t *block = NULL, *win = NULL;
    uint64_t off, end, t0;
    fg_status st = FG_OK;
    uint64_t i, next_free = 0;
    fg_recovered *tail = NULL;
    uint32_t idx = 0;
    fg_alloc_map amap;
    fg_partition_table pt;
    struct { uint64_t off, end; } claim[4096];
    int nclaim = 0;

    if (!source_path || !o || !res) return FG_ERR_INVALID;
    memset(res, 0, sizeof *res);
    memset(&hl, 0, sizeof hl);
    memset(&amap, 0, sizeof amap);
    memset(&pt, 0, sizeof pt);
    fg_make_id(res->report_id);
    fg_iso8601_utc(res->started_at, sizeof res->started_at);
    snprintf(res->source, sizeof res->source, "%s", source_path);

    st = fg_dev_open(source_path, FG_DEV_READ, &dev);
    if (st != FG_OK) { res->status = st; return st; }
    res->source_size = fg_dev_size(dev);
    if (!res->source_size) { fg_dev_close(dev); res->status = FG_ERR_IO; return FG_ERR_IO; }

    if (o->write_files && o->out_dir && fg_fs_mkdirs(o->out_dir) != FG_OK) {
        fg_dev_close(dev);
        res->status = FG_ERR_PERM;
        return FG_ERR_PERM;
    }

    t0 = fg_now_ms();
    sigs = fg_sig_table(&nsigs);


    if (o->do_metadata) {
        fg_parts_read(dev, &pt);
        if (pt.count) {
            int p;
            snprintf(res->fs_detected, sizeof res->fs_detected, "%s partition table, %d volume(s)",
                     pt.scheme == 2 ? "GPT" : "MBR", pt.count);
            for (p = 0; p < pt.count; p++) {
                fg_fs_ctx c;
                memset(&c, 0, sizeof c);
                c.dev = dev;
                c.vol_off = pt.parts[p].start_bytes;
                c.vol_size = pt.parts[p].size_bytes;
                c.opts = o;
                c.res = res;
                switch (pt.parts[p].fs) {
                case FG_FS_NTFS:  fg_ntfs_recover(&c); break;
                case FG_FS_FAT12:
                case FG_FS_FAT16:
                case FG_FS_FAT32: fg_fat_recover(&c, pt.parts[p].fs); break;
                case FG_FS_EXFAT: fg_exfat_recover(&c); break;
                case FG_FS_EXT2:
                case FG_FS_EXT3:
                case FG_FS_EXT4:  fg_ext_recover(&c); break;
                default: break;
                }
                if (!amap.valid && pt.parts[p].fs != FG_FS_UNKNOWN)
                    fg_alloc_map_load(&c, pt.parts[p].fs, &amap);
            }
        } else {
            uint8_t boot[4096];
            size_t got = 0;
            char label[72] = "";
            if (fg_dev_pread(dev, boot, sizeof boot, 0, &got) == FG_OK && got >= 512) {
                fg_fs_kind k = fg_fs_identify(boot, got, label, sizeof label);
                fg_fs_ctx c;
                memset(&c, 0, sizeof c);
                c.dev = dev; c.vol_off = 0; c.vol_size = res->source_size;
                c.opts = o; c.res = res;
                snprintf(res->fs_detected, sizeof res->fs_detected, "%s (whole-device volume)",
                         fg_fs_kind_name(k));
                switch (k) {
                case FG_FS_NTFS:  fg_ntfs_recover(&c); break;
                case FG_FS_FAT12:
                case FG_FS_FAT16:
                case FG_FS_FAT32: fg_fat_recover(&c, k); break;
                case FG_FS_EXFAT: fg_exfat_recover(&c); break;
                case FG_FS_EXT2:
                case FG_FS_EXT3:
                case FG_FS_EXT4:  fg_ext_recover(&c); break;
                default: break;
                }
                if (k != FG_FS_UNKNOWN && o->unallocated_only) {
                    fg_fs_ctx c2 = c;
                    fg_alloc_map_load(&c2, k, &amap);
                }
            }
        }
        res->metadata_recovered = res->files_recovered;
        {
            fg_recovered *r;
            for (r = res->files; r && r->next; r = r->next) ;
            tail = r;
            if (r) idx = r->index;
        }
        
        {
            fg_recovered *r;
            for (r = res->files; r && nclaim < (int)FG_ARRAY_LEN(claim); r = r->next) {
                int k;
                for (k = 0; k < r->fragments && k < 8 &&
                            nclaim < (int)FG_ARRAY_LEN(claim); k++) {
                    if (!r->frag_len[k]) continue;
                    claim[nclaim].off = r->frag_off[k];
                    claim[nclaim].end = r->frag_off[k] + r->frag_len[k];
                    nclaim++;
                }
            }
        }
    }

    if (!o->do_carve) goto finish;

    
    enabled = build_enabled(sigs, nsigs, o);
    if (!enabled) { st = FG_ERR_NOMEM; goto finish; }
    st = fg_ac_build(&ac, sigs, nsigs, enabled);
    if (st != FG_OK) goto finish;

    block = (uint8_t *)malloc((size_t)(o->block_size ? o->block_size : SCAN_BLOCK));
    if (!block) { st = FG_ERR_NOMEM; goto finish; }

    off = o->start_offset;
    end = o->end_offset ? FG_MIN(o->end_offset, res->source_size) : res->source_size;
    while (off < end) {
        size_t want = (size_t)FG_MIN((uint64_t)(o->block_size ? o->block_size : SCAN_BLOCK),
                                     end - off);
        size_t got = 0;
        if (fg_dev_pread(dev, block, want, off, &got) != FG_OK || !got) {
            off += 512;
            fg_ac_reset(ac);
            continue;
        }
        fg_ac_scan(ac, block, got, off, hit_add, &hl);
        res->bytes_scanned += got;
        off += got;
        if (fg_progress_report(&o->progress, "scan", off - o->start_offset,
                               end - o->start_offset, NULL)) {
            st = FG_ERR_ABORTED;
            goto finish;
        }
    }
    res->headers_seen = hl.n;
    if (hl.n > 1) qsort(hl.v, (size_t)hl.n, sizeof *hl.v, hit_cmp);

    
    win = (uint8_t *)malloc(WINDOW_CAP);
    if (!win) { st = FG_ERR_NOMEM; goto finish; }

    for (i = 0; i < hl.n; i++) {
        const fg_sig *s = &sigs[hl.v[i].sig];
        uint64_t hoff = hl.v[i].off;
        uint64_t cap, len = 0, got64 = 0;
        size_t got = 0;
        int quality = 0, structure_ok = 0, footer_ok = 0;
        fg_rec_method method = FG_REC_SIGNATURE;
        fg_recovered *r;
        uint64_t frag_off[8], frag_len[8];
        int nfrag = 1;

        if (o->max_results && res->files_recovered >= (uint64_t)o->max_results) break;
    
        if (hoff < next_free) continue;
        {
            int k, dup = 0;
            for (k = 0; k < nclaim; k++)
                if (hoff >= claim[k].off && hoff < claim[k].end) { dup = 1; break; }
            if (dup) continue;
        }
        if (o->unallocated_only && amap.valid && fg_alloc_map_is_allocated(&amap, hoff))
            continue;

        cap = FG_MIN(s->max_size, o->max_file_size ? o->max_file_size : s->max_size);
        cap = FG_MIN(cap, (uint64_t)WINDOW_CAP);
        cap = FG_MIN(cap, res->source_size - hoff);
        if (cap < s->min_size) continue;

        
        {
            uint64_t probe = FG_MIN(cap, (uint64_t)PROBE_SIZE);
            if (fg_dev_pread(dev, win, (size_t)probe, hoff, &got) != FG_OK ||
                got < s->min_size)
                continue;
            got64 = (uint64_t)got;
        }

        
        if (s->validate) {
            len = s->validate(win, got, s, &quality);
            if (len == 0) continue;                  
            if (len == FG_LEN_UNKNOWN && cap > got64) {
                uint64_t stages[2];
                int sg;
                stages[0] = FG_MIN(cap, (uint64_t)GROW_SIZE);
                stages[1] = cap;
                if (s->header_len < 4 && quality < 1) goto no_grow;
                for (sg = 0; sg < 2 && len == FG_LEN_UNKNOWN; sg++) {
                    size_t more = 0;
                    if (stages[sg] <= got64) continue;
                    if (sg == 1 && quality < 1) break;
                    if (fg_dev_pread(dev, win, (size_t)stages[sg], hoff, &more) != FG_OK ||
                        more <= got) break;
                    got = more;
                    got64 = (uint64_t)got;
                    len = s->validate(win, got, s, &quality);
                }
no_grow:
                if (len == 0) continue;
            } else if (len != FG_LEN_UNKNOWN && len > got64 && len <= cap) {
                size_t more = 0;
                if (fg_dev_pread(dev, win, (size_t)len, hoff, &more) == FG_OK &&
                    more >= len) {
                    got = more;
                    got64 = (uint64_t)got;
                }
            }
            if (len != FG_LEN_UNKNOWN && len && len <= got64) {
                structure_ok = 1;
                method = FG_REC_STRUCTURE;
            } else if (len != FG_LEN_UNKNOWN && len > got64) {
                len = got64;
                structure_ok = 0;
                method = FG_REC_SIGNATURE;
            } else {
                len = 0;
            }
        } else if (cap > got64 && (s->footer || s->header_len >= 8)) {
            size_t more = 0;
            if (fg_dev_pread(dev, win, (size_t)cap, hoff, &more) == FG_OK && more > got) {
                got = more;
                got64 = (uint64_t)got;
            }
        }
        if (!len && o->do_fragment && s->validate) {
            int q = 0;
            uint64_t fl = gap_carve(win, got, s, o->cluster_size ? o->cluster_size
                                                                 : amap.cluster_size,
                                    &q, frag_off, frag_len, &nfrag);
            if (fl) {
                len = fl;
                quality = q;
                structure_ok = 1;
                method = FG_REC_FRAGMENT;
            }
        }

        
        if (!len) {
            uint64_t f = find_footer(win, got, s, s->min_size);
            if (f) { len = f; footer_ok = 1; method = FG_REC_SIGNATURE; }
        }

        if (!len) {
            if (s->footer) continue;
            if (s->header_len < 8) continue;
            len = FG_MIN(got64, FG_MIN(s->max_size, (uint64_t)PROBE_SIZE));
            if (len < s->min_size) continue;
        }
        if (len < s->min_size) continue;

        r = (fg_recovered *)fg_xcalloc(1, sizeof *r);
        if (!r) { st = FG_ERR_NOMEM; goto finish; }
        r->index        = ++idx;
        r->ext          = s->ext;
        r->method       = method;
        r->src_offset   = hoff;
        r->size         = len;
        r->header_ok    = 1;
        r->structure_ok = structure_ok;
        r->footer_ok    = footer_ok || (structure_ok && quality >= 3);
        r->checksum_ok  = (quality >= 3 && structure_ok);
        r->fragments    = nfrag;
        if (nfrag > 1) {
            int k;
            for (k = 0; k < nfrag && k < 8; k++) {
                r->frag_off[k] = hoff + frag_off[k];
                r->frag_len[k] = frag_len[k];
            }
        } else {
            r->frag_off[0] = hoff;
            r->frag_len[0] = len;
        }
        if (amap.valid && fg_alloc_map_is_allocated(&amap, hoff))
            r->overwritten_risk = 80;

        snprintf(r->name, sizeof r->name, "%08u_%012llx.%s",
                 r->index, (unsigned long long)hoff, s->ext);
        {
            uint8_t *payload = win;
            uint8_t *tmp = NULL;
            if (nfrag > 1) {
                tmp = (uint8_t *)malloc((size_t)len);
                if (tmp) {
                    memcpy(tmp, win + frag_off[0], (size_t)frag_len[0]);
                    memcpy(tmp + frag_len[0], win + frag_off[1], (size_t)frag_len[1]);
                    payload = tmp;
                }
            }
            hash_and_score(r, payload, len, s);
            if (r->confidence >= o->min_confidence) {
                if (o->write_files && o->out_dir) {
                    if (write_out(o->out_dir, r->name, payload, len,
                                  r->out_path, sizeof r->out_path) != FG_OK)
                        snprintf(r->out_path, sizeof r->out_path, "(not written)");
                }
                if (tail) tail->next = r; else res->files = r;
                tail = r;
                res->files_recovered++;
                res->bytes_recovered += len;
                if (r->method == FG_REC_FRAGMENT) res->fragmented_recovered++;
                if (r->category < FG_CAT__COUNT) res->per_category[r->category]++;
                next_free = hoff + len;
            } else {
                res->rejected_low_confidence++;
                idx--;
                free(r);
            }
            free(tmp);
        }

        if ((i & 255) == 0 &&
            fg_progress_report(&o->progress, "carve", i, hl.n, NULL)) {
            st = FG_ERR_ABORTED;
            goto finish;
        }
    }

finish:
    res->seconds = (double)(fg_now_ms() - t0) / 1000.0;
    if (res->seconds > 0.0)
        res->throughput_mbs = (double)res->bytes_scanned / res->seconds / (1024.0 * 1024.0);
    fg_iso8601_utc(res->finished_at, sizeof res->finished_at);
    res->status = st;
    if (!res->fs_detected[0]) snprintf(res->fs_detected, sizeof res->fs_detected, "none detected");
    fg_alloc_map_free(&amap);
    free(hl.v);
    free(win);
    free(block);
    free(enabled);
    fg_ac_free(ac);
    fg_dev_close(dev);
    return st;
}

void fg_scan_result_free(fg_scan_result *res)
{
    fg_recovered *r, *n;
    if (!res) return;
    for (r = res->files; r; r = n) { n = r->next; free(r); }
    res->files = NULL;
}
