
#include "forge/fg_erase.h"
#include "forge/fg_audit.h"

#include <stdlib.h>
#include <string.h>

#include <stdio.h>

#define CHUNK (1u << 20)

void fg_file_opts_default(fg_file_opts *o)
{
    memset(o, 0, sizeof *o);
    o->method          = FG_M_DOD_3;
    o->verify          = FG_VERIFY_SAMPLE;
    o->recursive       = 1;
    o->remove_metadata = 1;

    o->wipe_slack      = 1;
    o->keep_going      = 1;
}


static int glob_one(const char *pat, const char *s)
{
    while (*pat) {
        if (*pat == '*') {
            pat++;
            if (!*pat) return 1;
            while (*s) { if (glob_one(pat, s)) return 1; s++; }
            return glob_one(pat, s);
        }
        if (*pat == '?') { if (!*s) return 0; pat++; s++; continue; }
        {
            int a = *pat, b = *s;
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) return 0;
        }
        pat++; s++;
    }
    return !*s;
}

static int glob_list(const char *list, const char *name)
{
    char buf[1024], *p, *save;
    if (!list || !*list) return 1;
    snprintf(buf, sizeof buf, "%s", list);
    p = buf;
    while (p) {
        save = strchr(p, ',');
        if (save) *save = '\0';
        while (*p == ' ') p++;
        if (*p && glob_one(p, name)) return 1;
        p = save ? save + 1 : NULL;
    }
    return 0;
}

static void random_name(fg_rng *rng, char *out, size_t len)
{
    static const char cs[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t i;
    for (i = 0; i < len; i++) out[i] = cs[fg_rng_u64(rng) % (sizeof cs - 1)];
    out[len] = '\0';
}

static void dir_of(const char *path, char *out, size_t outsz)
{
    const char *s1 = strrchr(path, '/');
    const char *s2 = strrchr(path, '\\');
    const char *cut = (s1 > s2) ? s1 : s2;
    if (!cut) { snprintf(out, outsz, "."); return; }
    {
        size_t n = (size_t)(cut - path);
        if (n >= outsz) n = outsz - 1;
        memcpy(out, path, n);
        out[n] = '\0';
        if (!n) snprintf(out, outsz, "%c", FG_PATH_SEP);
    }
}


static fg_status overwrite_stream(fg_file *f, const fg_method_def *def,
                                  fg_rng *rng, uint64_t len,
                                  const fg_progress *pg, const char *label,
                                  int *passes_done)
{
    uint8_t *buf = (uint8_t *)malloc(CHUNK);
    int pass;
    fg_status st = FG_OK;
    if (!buf) return FG_ERR_NOMEM;

    for (pass = 0; pass < def->pass_count; pass++) {
        uint64_t off = 0;
        int det = fg_pattern_deterministic(def, pass);
        if (det && def->passes[pass].kind != FG_PAT_TRIPLE)
            fg_pattern_fill(def, pass, rng, buf, CHUNK, 0);
        while (off < len) {
            size_t want = (size_t)FG_MIN((uint64_t)CHUNK, len - off), put = 0;
            if (!det || def->passes[pass].kind == FG_PAT_TRIPLE)
                fg_pattern_fill(def, pass, rng, buf, want, off);
            if (fg_file_write_at(f, buf, want, off, &put) != FG_OK || put != want) {
                st = FG_ERR_IO;
                goto out;
            }
            off += put;
        }
        
        fg_file_sync(f);
        if (passes_done) *passes_done = pass + 1;
        if (fg_progress_report(pg, label, (uint64_t)(pass + 1),
                               (uint64_t)def->pass_count, NULL)) {
            st = FG_ERR_ABORTED;
            goto out;
        }
    }
out:
    free(buf);
    return st;
}


#define VERIFY_WIN 65536u

static int verify_spots(uint64_t len, fg_verify_mode mode, uint64_t *spots, size_t *win)
{
    *win = (size_t)FG_MIN((uint64_t)VERIFY_WIN, len ? len : 1);
    if (mode == FG_VERIFY_FULL || len <= (uint64_t)*win) { spots[0] = 0; return 1; }
    spots[0] = 0;
    spots[1] = (len - *win) / 2;
    spots[2] = len - *win;
    return 3;
}


static int sample_digest(fg_file *f, uint64_t len, fg_verify_mode mode, uint8_t out[32])
{
    uint64_t spots[3];
    size_t win;
    int n = verify_spots(len, mode, spots, &win), i;
    uint8_t *rd = (uint8_t *)malloc(win);
    fg_sha256 sh;
    if (!rd) return 0;
    fg_sha256_init(&sh);
    if (mode == FG_VERIFY_FULL) {
        uint64_t off = 0;
        while (off < len) {
            size_t want = (size_t)FG_MIN((uint64_t)win, len - off), got = 0;
            if (fg_file_read_at(f, rd, want, off, &got) != FG_OK || !got) break;
            fg_sha256_update(&sh, rd, got);
            off += got;
        }
    } else {
        for (i = 0; i < n; i++) {
            size_t want = (size_t)FG_MIN((uint64_t)win, len - spots[i]), got = 0;
            if (fg_file_read_at(f, rd, want, spots[i], &got) != FG_OK || !got) continue;
            fg_sha256_update(&sh, rd, got);
        }
    }
    fg_sha256_final(&sh, out);
    free(rd);
    return 1;
}


static int verify_stream(fg_file *f, const fg_method_def *def, uint64_t len,
                         fg_verify_mode mode, const uint8_t before[32])
{
    uint8_t *rd, *exp;
    int last = def->pass_count - 1;
    int det = fg_pattern_deterministic(def, last);
    int ok = 1;
    uint64_t spots[3];
    size_t win;
    int i, nspots;

    if (mode == FG_VERIFY_NONE || !len) return 1;

    if (!det) {
        uint8_t after[32];
        if (!sample_digest(f, len, mode, after)) return 0;
        if (before && fg_ct_equal(before, after, 32)) return 0;  /* nothing changed */
    }

    nspots = verify_spots(len, mode, spots, &win);
    rd  = (uint8_t *)malloc(win);
    exp = (uint8_t *)malloc(win);
    if (!rd || !exp) { free(rd); free(exp); return 0; }

    if (mode == FG_VERIFY_FULL) {
        uint64_t off = 0;
        while (off < len && ok) {
            size_t want = (size_t)FG_MIN((uint64_t)win, len - off), got = 0;
            if (fg_file_read_at(f, rd, want, off, &got) != FG_OK || !got) { ok = 0; break; }
            if (det) {
                size_t k;
                fg_pattern_fill(def, last, NULL, exp, got, off);
                for (k = 0; k < got; k++) if (rd[k] != exp[k]) { ok = 0; break; }
            } else if (got >= 4096 && fg_shannon_entropy(rd, got) < 7.5) {
                ok = 0;
            }
            off += got;
        }
        free(rd); free(exp);
        return ok;
    }

    for (i = 0; i < nspots && ok; i++) {
        size_t want = (size_t)FG_MIN((uint64_t)win, len - spots[i]), got = 0;
        if (fg_file_read_at(f, rd, want, spots[i], &got) != FG_OK || !got) { ok = 0; break; }
        if (det) {
            size_t k;
            fg_pattern_fill(def, last, NULL, exp, got, spots[i]);
            for (k = 0; k < got; k++) if (rd[k] != exp[k]) { ok = 0; break; }
        } else if (got >= 4096 && fg_shannon_entropy(rd, got) < 7.5) {
            ok = 0;
        }
    }
    free(rd); free(exp);
    return ok;
}


static uint64_t wipe_slack(fg_file *f, const char *path, uint64_t len,
                           const fg_method_def *def, fg_rng *rng)
{
    uint32_t clus = 4096;
    uint64_t padded, slack;
    uint8_t *buf;
    size_t put = 0;
    FG_UNUSED(def);
    fg_fs_free_space(path, NULL, NULL, &clus);
    if (!clus) clus = 4096;
    padded = ((len + clus - 1) / clus) * clus;
    slack = padded - len;
    if (!slack) return 0;
    buf = (uint8_t *)malloc((size_t)slack);
    if (!buf) return 0;
    fg_rng_fill(rng, buf, (size_t)slack);
    if (fg_file_write_at(f, buf, (size_t)slack, len, &put) == FG_OK) fg_file_sync(f);
    free(buf);
    return put;
}

static fg_status erase_one(const char *path, uint64_t size,
                           const fg_file_opts *o, fg_rng *rng,
                           fg_file_record *rec)
{
    const fg_method_def *def = fg_method_get(o->method);
    fg_file *f = NULL;
    fg_status st;
    
    char dir[4000], cur[4096], next[4096], rnd[64];
    int i;

    snprintf(rec->path, sizeof rec->path, "%s", path);
    rec->size = size;

    if (o->dry_run) {
        rec->status = FG_OK;
        snprintf(rec->message, sizeof rec->message,
                 "dry run: %d pass(es) of %s", def->pass_count, def->name);
        return FG_OK;
    }

    fg_fs_clear_attrs(path);

    
    if (o->remove_metadata) {
        rec->alt_streams_removed = fg_fs_wipe_alt_streams(path);
        rec->xattrs_removed      = fg_fs_wipe_xattrs(path);
    }

    st = fg_file_open_rw(path, 1, &f);
    if (st != FG_OK) {
        rec->status = st;
        snprintf(rec->message, sizeof rec->message, "cannot open: %s", fg_strerror(st));
        return st;
    }

    if (size) {
        uint8_t before[32];
        int have_before = 0;
        if (o->verify != FG_VERIFY_NONE &&
            !fg_pattern_deterministic(def, def->pass_count - 1)) {
            have_before = sample_digest(f, size, o->verify, before);
            if (have_before) fg_hex_encode(before, 32, rec->sha256_before);
        }
        st = overwrite_stream(f, def, rng, size, &o->progress, "overwrite", &rec->passes);
        if (st != FG_OK) {
            fg_file_close(f);
            rec->status = st;
            snprintf(rec->message, sizeof rec->message, "overwrite failed: %s",
                     fg_strerror(st));
            return st;
        }
        rec->verified = verify_stream(f, def, size, o->verify,
                                      have_before ? before : NULL);
        if (!rec->verified && o->verify != FG_VERIFY_NONE) {
            fg_file_close(f);
            rec->status = FG_ERR_VERIFY;
            snprintf(rec->message, sizeof rec->message,
                     "overwrite could not be verified; the file may be on a "
                     "copy-on-write or compressed volume");
            return FG_ERR_VERIFY;
        }
    } else {
        rec->verified = 1;
    }

    if (o->wipe_slack) rec->slack_bytes = wipe_slack(f, path, size, def, rng);

    
    fg_file_close(f);
    {
        uint64_t l = size;
        while (l > 4096) { l /= 4; fg_fs_truncate(path, l); }
        fg_fs_truncate(path, 0);
    }

    
    snprintf(cur, sizeof cur, "%s", path);
    dir_of(path, dir, sizeof dir);
    for (i = 0; i < 5; i++) {
        size_t nlen = 16 - (size_t)i * 3;
        if (nlen < 4) nlen = 4;
        random_name(rng, rnd, nlen);
        snprintf(next, sizeof next, "%s%c%s", dir, FG_PATH_SEP, rnd);
        if (fg_fs_rename(cur, next) != FG_OK) break;
        snprintf(cur, sizeof cur, "%s", next);
        rec->renames++;
    }

    if (o->remove_metadata) fg_fs_set_times(cur, 0, 0);

    st = fg_fs_remove(cur);
    if (st != FG_OK) {
        rec->status = st;
        snprintf(rec->message, sizeof rec->message, "unlink failed: %s", fg_strerror(st));
        return st;
    }
    rec->status = FG_OK;
    snprintf(rec->message, sizeof rec->message, "erased with %s (%d passes)",
             def->name, def->pass_count);
    return FG_OK;
}


typedef struct path_node {
    char path[4096];
    uint64_t size;
    int is_dir;
    struct path_node *next;
} path_node;

typedef struct {
    path_node *head, *tail;
    const fg_file_opts *o;
    uint64_t count;
} collect_ctx;

static int collect_cb(void *user, const fg_fs_entry *e)
{
    collect_ctx *c = (collect_ctx *)user;
    path_node *n;
    if (e->is_symlink && !c->o->follow_symlinks && !e->is_dir) {

    }
    if (!e->is_dir) {
        if (!glob_list(c->o->include_glob, e->name)) return 0;
        if (c->o->exclude_glob && glob_list(c->o->exclude_glob, e->name)) return 0;
        if (c->o->max_size && e->size > c->o->max_size) return 0;
    }
    n = (path_node *)fg_xcalloc(1, sizeof *n);
    if (!n) return 1;
    snprintf(n->path, sizeof n->path, "%s", e->path);
    n->size = e->size;
    n->is_dir = e->is_dir;
    if (c->tail) c->tail->next = n; else c->head = n;
    c->tail = n;
    if (!e->is_dir) c->count++;
    return 0;
}

fg_status fg_file_erase_paths(const char *const *paths, int npaths,
                              const fg_file_opts *o, fg_file_result *res)
{
    collect_ctx cc;
    path_node *n, *next;
    fg_rng rng;
    uint64_t t0, done = 0;
    int i;
    const fg_method_def *def;

    if (!paths || npaths <= 0 || !o || !res) return FG_ERR_INVALID;
    memset(res, 0, sizeof *res);
    memset(&cc, 0, sizeof cc);
    cc.o = o;
    def = fg_method_get(o->method);
    res->method = o->method;
    snprintf(res->method_name, sizeof res->method_name, "%s", def->name);
    fg_make_id(res->report_id);
    fg_iso8601_utc(res->started_at, sizeof res->started_at);
    fg_rng_init(&rng);
    t0 = fg_now_ms();

    for (i = 0; i < npaths; i++) {
        fg_fs_entry e;
        if (fg_fs_stat(paths[i], &e) != FG_OK) {
            res->files_failed++;
            continue;
        }
        if (e.is_dir) {
            fg_fs_walk(paths[i], o->recursive, collect_cb, &cc);

            {
                path_node *d = (path_node *)fg_xcalloc(1, sizeof *d);
                if (d) {
                    snprintf(d->path, sizeof d->path, "%s", paths[i]);
                    d->is_dir = 1;
                    if (cc.tail) cc.tail->next = d; else cc.head = d;
                    cc.tail = d;
                }
            }
        } else {
            collect_cb(&cc, &e);
        }
    }
    res->files_total = cc.count;


    for (n = cc.head; n; n = n->next) {
        fg_file_record *rec;
        if (n->is_dir) continue;
        rec = (fg_file_record *)fg_xcalloc(1, sizeof *rec);
        if (!rec) break;
        if (erase_one(n->path, n->size, o, &rng, rec) == FG_OK) {
            res->files_erased++;
            res->bytes_erased    += n->size;
            res->slack_bytes     += rec->slack_bytes;
            res->streams_removed += (uint64_t)rec->alt_streams_removed;
            res->xattrs_removed  += (uint64_t)rec->xattrs_removed;
        } else {
            res->files_failed++;
            if (!o->keep_going) {
                rec->next = res->records;
                res->records = rec;
                res->status = rec->status;
                goto finish;
            }
        }
        rec->next = res->records;
        res->records = rec;
        done++;
        if (fg_progress_report(&o->progress, "erase", done, res->files_total, n->path)) {
            res->status = FG_ERR_ABORTED;
            goto finish;
        }
    }

    if (o->remove_empty_dirs && !o->dry_run) {

        char **dirs = NULL;
        int ndirs = 0, cap = 0, a, b;
        for (n = cc.head; n; n = n->next) {
            if (!n->is_dir) continue;
            if (ndirs == cap) {
                int ncap = cap ? cap * 2 : 64;
                char **nd = (char **)realloc(dirs, (size_t)ncap * sizeof *nd);
                if (!nd) break;
                dirs = nd;
                cap = ncap;
            }
            dirs[ndirs++] = n->path;
        }
        for (a = 0; a < ndirs; a++)
            for (b = a + 1; b < ndirs; b++)
                if (strlen(dirs[b]) > strlen(dirs[a])) {
                    char *t = dirs[a]; dirs[a] = dirs[b]; dirs[b] = t;
                }
        for (a = 0; a < ndirs; a++)
            if (fg_fs_rmdir(dirs[a]) == FG_OK) res->dirs_removed++;
        free(dirs);
    }

finish:
    for (n = cc.head; n; n = next) { next = n->next; free(n); }
    res->seconds = (double)(fg_now_ms() - t0) / 1000.0;
    fg_iso8601_utc(res->finished_at, sizeof res->finished_at);
    if (res->status == FG_OK && res->files_failed && !res->files_erased)
        res->status = FG_ERR_GENERIC;
    return res->status;
}

void fg_file_result_free(fg_file_result *res)
{
    fg_file_record *r, *n;
    if (!res) return;
    for (r = res->records; r; r = n) { n = r->next; free(r); }
    res->records = NULL;
}


fg_status fg_wipe_free_space(const char *volume_path, fg_method m,
                             int wipe_dir_entries,
                             const fg_progress *pg, fg_freespace_result *res)
{
    const fg_method_def *def = fg_method_get(m);
    char dir[4096], fname[4160];
    uint64_t freeb = 0, total = 0, t0;
    uint32_t clus = 4096;
    fg_rng rng;
    uint8_t *buf;
    int fileno = 0;
    fg_status st = FG_OK;

    if (!volume_path || !res) return FG_ERR_INVALID;
    memset(res, 0, sizeof *res);
    if (fg_fs_free_space(volume_path, &freeb, &total, &clus) != FG_OK)
        return FG_ERR_NOTFOUND;
    res->free_before_gb = (double)freeb / (1024.0 * 1024.0 * 1024.0);

    snprintf(dir, sizeof dir, "%s%c.forge_wipe", volume_path, FG_PATH_SEP);
    if (fg_fs_mkdirs(dir) != FG_OK) return FG_ERR_PERM;

    buf = (uint8_t *)malloc(CHUNK);
    if (!buf) { fg_fs_rmdir(dir); return FG_ERR_NOMEM; }
    fg_rng_init(&rng);
    t0 = fg_now_ms();


    if (freeb > 32u * 1024u * 1024u) freeb -= 32u * 1024u * 1024u;

    while (freeb > 0 && st == FG_OK) {
        fg_file *f = NULL;
        uint64_t chunk_target = FG_MIN(freeb, (uint64_t)1 << 30);   /* 1 GiB files */
        uint64_t written = 0;
        FILE *fp;

        snprintf(fname, sizeof fname, "%s%ckv_%04d.tmp", dir, FG_PATH_SEP, fileno++);
        fp = fopen(fname, "wb");
        if (!fp) break;
        fclose(fp);
        if (fg_file_open_rw(fname, 1, &f) != FG_OK) break;

        fg_pattern_fill(def, def->pass_count - 1, &rng, buf, CHUNK, 0);
        while (written < chunk_target) {
            size_t want = (size_t)FG_MIN((uint64_t)CHUNK, chunk_target - written), put = 0;
            if (!fg_pattern_deterministic(def, def->pass_count - 1))
                fg_rng_fill(&rng, buf, want);
            if (fg_file_write_at(f, buf, want, written, &put) != FG_OK || !put) break;
            written += put;
            res->bytes_written += put;
            if (fg_progress_report(pg, "free-space", res->bytes_written,
                                   res->bytes_written + freeb, NULL)) {
                st = FG_ERR_ABORTED;
                break;
            }
        }
        fg_file_sync(f);
        fg_file_close(f);
        if (!written) { fg_fs_remove(fname); break; }
        freeb = (freeb > written) ? freeb - written : 0;
        if (fileno > 4096) break;   /* safety valve */
    }


    if (wipe_dir_entries && st == FG_OK) {
        int k;
        for (k = 0; k < 8192; k++) {
            FILE *fp;
            char nm[4160];
            snprintf(nm, sizeof nm, "%s%ckvm_%06d_padding_padding_padding.tmp",
                     dir, FG_PATH_SEP, k);
            fp = fopen(nm, "wb");
            if (!fp) break;
            fwrite(buf, 1, 64, fp);
            fclose(fp);
            res->mft_records_wiped++;
        }
    }


    {
        fg_file_opts fo;
        fg_file_result fr;
        const char *p = dir;
        fg_file_opts_default(&fo);
        fo.method = FG_M_ZERO;
        fo.verify = FG_VERIFY_NONE;
        fo.recursive = 1;
        fo.remove_metadata = 0;
        fo.wipe_slack = 0;
        fo.remove_empty_dirs = 1;
        fg_file_erase_paths(&p, 1, &fo, &fr);
        fg_file_result_free(&fr);
    }
    fg_fs_rmdir(dir);

    free(buf);
    res->seconds = (double)(fg_now_ms() - t0) / 1000.0;
    fg_fs_free_space(volume_path, &freeb, &total, &clus);
    res->free_after_gb = (double)freeb / (1024.0 * 1024.0 * 1024.0);
    return st;
}
