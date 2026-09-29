
#include "fs_internal.h"
#include "forge/fg_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void fg_utf16le_to_utf8(const uint8_t *src, int chars, char *out, size_t outsz)
{
    size_t o = 0;
    int i;
    for (i = 0; i < chars && o + 4 < outsz; i++) {
        uint16_t c = fg_rd16le(src + i * 2);
        if (!c) break;
        if (c < 0x80) {
            out[o++] = (char)c;
        } else if (c < 0x800) {
            out[o++] = (char)(0xC0 | (c >> 6));
            out[o++] = (char)(0x80 | (c & 0x3F));
        } else {
            out[o++] = (char)(0xE0 | (c >> 12));
            out[o++] = (char)(0x80 | ((c >> 6) & 0x3F));
            out[o++] = (char)(0x80 | (c & 0x3F));
        }
    }
    out[o] = '\0';
}


static void sanitize(char *s)
{
    for (; *s; s++)
        if (strchr("\\/:*?\"<>|", *s) || (unsigned char)*s < 0x20) *s = '_';
}

static const char *ext_of(const char *name)
{
    const char *dot = strrchr(name, '.');
    return (dot && dot[1] && strlen(dot + 1) <= 8) ? dot + 1 : "bin";
}

fg_status fg_fs_emit(fg_fs_ctx *c, const char *name, fg_fs_kind fs,
                     const fg_run *runs, int nruns,
                     const uint8_t *resident, uint64_t size,
                     int64_t mtime, int deleted, int fragmented)
{
    const fg_scan_opts *o = c->opts;
    fg_scan_result *res = c->res;
    fg_recovered *r, *tail;
    uint8_t *data = NULL;
    uint64_t want;
    const fg_sig *sig;
    char safe[512];

    if (!size) return FG_OK;
    if (o->max_results && res->files_recovered >= (uint64_t)o->max_results) return FG_OK;
    want = FG_MIN(size, o->max_file_size ? o->max_file_size : size);
    if (want > 512ull * 1024 * 1024) want = 512ull * 1024 * 1024;

    snprintf(safe, sizeof safe, "%s", name && *name ? name : "unnamed");
    sanitize(safe);
    sig = fg_sig_by_ext(ext_of(safe));   /* refined below once we have bytes */

    /* Type filtering applies to metadata recovery too. */
    if (o->types && *o->types && sig) {
        /* reuse the same comma-list test the carver uses */
        const char *p = o->types;
        int found = 0;
        while (*p && !found) {
            const char *cm = strchr(p, ',');
            size_t len = cm ? (size_t)(cm - p) : strlen(p);
            if (len == strlen(sig->ext)) {
                size_t k; int eq = 1;
                for (k = 0; k < len; k++) {
                    int a = p[k], b = sig->ext[k];
                    if (a >= 'A' && a <= 'Z') a += 32;
                    if (b >= 'A' && b <= 'Z') b += 32;
                    if (a != b) { eq = 0; break; }
                }
                found = eq;
            }
            if (!cm) break;
            p = cm + 1;
        }
        if (!found) return FG_OK;
    }

    data = (uint8_t *)malloc((size_t)want);
    if (!data) return FG_ERR_NOMEM;

    if (resident) {
        memcpy(data, resident, (size_t)want);
    } else {
        uint64_t filled = 0;
        int i;
        for (i = 0; i < nruns && filled < want; i++) {
            uint64_t take = FG_MIN(runs[i].len, want - filled);
            size_t got = 0;
            if (fg_dev_pread(c->dev, data + filled, (size_t)take,
                             runs[i].off, &got) != FG_OK || !got) {
                /* A run that no longer reads is a strong hint the clusters
                 * were reallocated; keep what we have. */
                memset(data + filled, 0, (size_t)take);
                got = (size_t)take;
            }
            filled += got;
        }
        if (!filled) { free(data); return FG_OK; }
        want = filled;
    }

    r = (fg_recovered *)fg_xcalloc(1, sizeof *r);
    if (!r) { free(data); return FG_ERR_NOMEM; }

    for (tail = res->files; tail && tail->next; tail = tail->next) ;
    r->index = tail ? tail->index + 1 : 1;
    snprintf(r->name, sizeof r->name, "%s", safe);
    r->ext          = sig ? sig->ext : ext_of(safe);
    r->method       = FG_REC_METADATA;
    r->src_offset   = runs && nruns ? runs[0].off : c->vol_off;
    r->size         = want;
    r->fragments    = fragmented ? (nruns > 8 ? 8 : nruns) : 1;
    r->mtime        = mtime;
    r->deleted_flag = deleted;
    r->header_ok    = 1;
    if (runs && nruns) {
        int k;
        for (k = 0; k < nruns && k < 8; k++) {
            r->frag_off[k] = runs[k].off;
            r->frag_len[k] = runs[k].len;
        }
    }

    sig = sig ? fg_sig_match(data, (size_t)want, sig->ext)
              : fg_sig_match(data, (size_t)want, NULL);
    if (sig && want >= sig->header_len + sig->header_off) {
        if (!memcmp(data + sig->header_off, sig->header, sig->header_len)) {
            r->header_ok = 1;
            r->ext = sig->ext;
            if (sig->validate) {
                int q = 0;
                uint64_t len = sig->validate(data, (size_t)want, sig, &q);
                if (len && len != FG_LEN_UNKNOWN) {
                    r->structure_ok = 1;
                    r->checksum_ok = (q >= 3);
                    if (len == want) r->footer_ok = 1;
                }
            }
        } else {
            r->header_ok = 0;
            r->overwritten_risk = 70;
        }
    }

    {
        uint8_t d[32], m[16];
        fg_sha256 sh;
        fg_md5 md;
        fg_sha256_init(&sh);
        fg_md5_init(&md);
        fg_sha256_update(&sh, data, (size_t)want);
        fg_md5_update(&md, data, (size_t)want);
        fg_sha256_final(&sh, d);
        fg_md5_final(&md, m);
        fg_hex_encode(d, 32, r->sha256);
        fg_hex_encode(m, 16, r->md5);
    }
    r->category = fg_classify(data, (size_t)want, sig);
    fg_confidence_score(r, data, (size_t)want, sig);

    if (r->confidence < o->min_confidence) {
        res->rejected_low_confidence++;
        free(r);
        free(data);
        return FG_OK;
    }

    if (o->write_files && o->out_dir) {
        char fname[4096];
        FILE *f;
        snprintf(fname, sizeof fname, "%s%c%s_%05u_%s", o->out_dir, FG_PATH_SEP,
                 fg_fs_kind_name(fs), r->index,
                 o->preserve_names ? safe : "recovered");
        f = fopen(fname, "wb");
        if (f) {
            fwrite(data, 1, (size_t)want, f);
            fclose(f);
            snprintf(r->out_path, sizeof r->out_path, "%s", fname);
        } else {
            snprintf(r->out_path, sizeof r->out_path, "(not written)");
        }
    }

    if (tail) tail->next = r; else res->files = r;
    res->files_recovered++;
    res->bytes_recovered += want;
    if (r->fragments > 1) res->fragmented_recovered++;
    if (r->category < FG_CAT__COUNT) res->per_category[r->category]++;
    free(data);
    return FG_OK;
}
