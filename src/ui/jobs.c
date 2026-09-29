
#include "forge/fg_ui.h"
#include "forge/fg_json.h"
#include "forge/fg_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_JOBS 64

struct fg_job {
    char          id[33];
    char          title[192];
    fg_job_kind   kind;
    fg_job_state  state;
    char          phase[64];
    char          detail[512];
    uint64_t      done, total;
    double        started_ms;
    double        finished_ms;
    int           cancel;
    int           used;
    fg_status     status;
    char          message[256];

    /* inputs (owned copies) */
    char          target[4096];
    char        **paths;
    int           npaths;
    fg_drive_opts dopts;
    fg_file_opts  fopts;
    fg_scan_opts  sopts;
    char          out_dir[4096];
    char          types[512];
    char          confirm[128];
    char          case_id[96];
    char          operator_name[96];
    fg_method     method;

    /* results */
    fg_drive_result      dres;
    fg_file_result       fres;
    fg_scan_result       sres;
    fg_freespace_result  wres;
    int                  has_result;

    fg_thread    *thread;
};

static fg_job    g_jobs[MAX_JOBS];
static fg_mutex *g_lock;
static fg_audit *g_audit;

fg_status fg_jobs_init(fg_audit *audit)
{
    memset(g_jobs, 0, sizeof g_jobs);
    g_audit = audit;
    return fg_mutex_create(&g_lock);
}

void fg_jobs_shutdown(void)
{
    int i;
    for (i = 0; i < MAX_JOBS; i++) {
        if (g_jobs[i].used && g_jobs[i].state == FG_JOB_RUNNING) g_jobs[i].cancel = 1;
    }
    for (i = 0; i < MAX_JOBS; i++) {
        if (g_jobs[i].thread) { fg_thread_join(g_jobs[i].thread); g_jobs[i].thread = NULL; }
        fg_file_result_free(&g_jobs[i].fres);
        fg_scan_result_free(&g_jobs[i].sres);
        if (g_jobs[i].paths) {
            int k;
            for (k = 0; k < g_jobs[i].npaths; k++) free(g_jobs[i].paths[k]);
            free(g_jobs[i].paths);
        }
    }
    fg_mutex_destroy(g_lock);
    g_lock = NULL;
}

fg_job *fg_job_create(fg_job_kind kind, const char *title)
{
    int i;
    fg_job *j = NULL;
    fg_mutex_lock(g_lock);
    for (i = 0; i < MAX_JOBS; i++) {
        if (!g_jobs[i].used) { j = &g_jobs[i]; break; }
    }
    /* Reclaim the oldest finished slot when the table is full. */
    if (!j) {
        double oldest = 0;
        for (i = 0; i < MAX_JOBS; i++) {
            if (g_jobs[i].state == FG_JOB_RUNNING) continue;
            if (!j || g_jobs[i].finished_ms < oldest) { j = &g_jobs[i]; oldest = g_jobs[i].finished_ms; }
        }
        if (j) {
            if (j->thread) { fg_thread_join(j->thread); j->thread = NULL; }
            fg_file_result_free(&j->fres);
            fg_scan_result_free(&j->sres);
        }
    }
    if (j) {
        memset(j, 0, sizeof *j);
        j->used = 1;
        j->kind = kind;
        j->state = FG_JOB_IDLE;
        fg_make_id(j->id);
        snprintf(j->title, sizeof j->title, "%s", title ? title : "job");
    }
    fg_mutex_unlock(g_lock);
    return j;
}

const char *fg_job_id(const fg_job *j) { return j ? j->id : ""; }

fg_job *fg_job_find(const char *id)
{
    int i;
    if (!id) return NULL;
    for (i = 0; i < MAX_JOBS; i++)
        if (g_jobs[i].used && !strcmp(g_jobs[i].id, id)) return &g_jobs[i];
    return NULL;
}

void fg_job_cancel(const char *id)
{
    fg_job *j = fg_job_find(id);
    if (j && j->state == FG_JOB_RUNNING) j->cancel = 1;
}

/* ---- progress bridge ----------------------------------------------------- */
static int job_progress(void *user, const char *phase, uint64_t done,
                        uint64_t total, const char *detail)
{
    fg_job *j = (fg_job *)user;
    fg_mutex_lock(g_lock);
    snprintf(j->phase, sizeof j->phase, "%s", phase ? phase : "");
    if (detail) snprintf(j->detail, sizeof j->detail, "%s", detail);
    j->done = done;
    j->total = total;
    fg_mutex_unlock(g_lock);
    return j->cancel;
}

static void job_finish(fg_job *j, fg_status st, const char *msg)
{
    fg_mutex_lock(g_lock);
    j->status = st;
    j->finished_ms = (double)fg_now_ms();
    j->state = j->cancel ? FG_JOB_CANCELLED : (st == FG_OK ? FG_JOB_DONE : FG_JOB_FAILED);
    snprintf(j->message, sizeof j->message, "%s", msg ? msg : fg_strerror(st));
    j->has_result = 1;
    fg_mutex_unlock(g_lock);
}

/* ---- workers ------------------------------------------------------------- */
static void worker_drive(void *arg)
{
    fg_job *j = (fg_job *)arg;
    fg_status st;
    j->dopts.progress.fn = job_progress;
    j->dopts.progress.user = j;
    j->dopts.confirm_token = j->confirm[0] ? j->confirm : NULL;
    j->dopts.case_id = j->case_id;
    j->dopts.operator_name = j->operator_name;
    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_ERASE_BEGIN, FG_OK, j->target,
                        "\"job\":\"%s\",\"method\":\"%s\"", j->id,
                        fg_method_get(j->dopts.method)->cli_name);
    st = fg_drive_erase(j->target, &j->dopts, &j->dres);
    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_ERASE_END, st, j->target,
                        "\"job\":\"%s\",\"bytes\":%llu,\"verified\":%s,\"report\":\"%s\"",
                        j->id, (unsigned long long)j->dres.bytes_written,
                        j->dres.verify.passed ? "true" : "false", j->dres.report_id);
    job_finish(j, st, j->dres.message);
}

static void worker_files(void *arg)
{
    fg_job *j = (fg_job *)arg;
    fg_status st;
    j->fopts.progress.fn = job_progress;
    j->fopts.progress.user = j;
    j->fopts.case_id = j->case_id;
    j->fopts.operator_name = j->operator_name;
    st = fg_file_erase_paths((const char *const *)j->paths, j->npaths, &j->fopts, &j->fres);
    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_FILE_ERASE, st, j->paths && j->npaths ? j->paths[0] : "",
                        "\"job\":\"%s\",\"erased\":%llu,\"failed\":%llu,\"bytes\":%llu",
                        j->id, (unsigned long long)j->fres.files_erased,
                        (unsigned long long)j->fres.files_failed,
                        (unsigned long long)j->fres.bytes_erased);
    job_finish(j, st, "file erasure complete");
}

static void worker_freespace(void *arg)
{
    fg_job *j = (fg_job *)arg;
    fg_progress pg;
    fg_status st;
    pg.fn = job_progress;
    pg.user = j;
    st = fg_wipe_free_space(j->target, j->method, 1, &pg, &j->wres);
    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_FREESPACE, st, j->target,
                        "\"job\":\"%s\",\"bytes\":%llu", j->id,
                        (unsigned long long)j->wres.bytes_written);
    job_finish(j, st, "free space wiped");
}

static void worker_scan(void *arg)
{
    fg_job *j = (fg_job *)arg;
    fg_status st;
    j->sopts.progress.fn = job_progress;
    j->sopts.progress.user = j;
    j->sopts.out_dir = j->out_dir[0] ? j->out_dir : NULL;
    j->sopts.types = j->types[0] ? j->types : NULL;
    j->sopts.case_id = j->case_id;
    j->sopts.operator_name = j->operator_name;
    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_SCAN_BEGIN, FG_OK, j->target, "\"job\":\"%s\"", j->id);
    st = fg_carve_run(j->target, &j->sopts, &j->sres);
    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_SCAN_END, st, j->target,
                        "\"job\":\"%s\",\"recovered\":%llu,\"bytes\":%llu,\"report\":\"%s\"",
                        j->id, (unsigned long long)j->sres.files_recovered,
                        (unsigned long long)j->sres.bytes_recovered, j->sres.report_id);
    job_finish(j, st, "recovery scan complete");
}

static fg_status launch(fg_job *j, void (*fn)(void *))
{
    j->state = FG_JOB_RUNNING;
    j->started_ms = (double)fg_now_ms();
    return fg_thread_start(&j->thread, fn, j);
}

fg_status fg_job_start_drive(fg_job *j, const char *device, const fg_drive_opts *o)
{
    if (!j || !device || !o) return FG_ERR_INVALID;
    snprintf(j->target, sizeof j->target, "%s", device);
    j->dopts = *o;
    if (o->confirm_token) snprintf(j->confirm, sizeof j->confirm, "%s", o->confirm_token);
    if (o->case_id) snprintf(j->case_id, sizeof j->case_id, "%s", o->case_id);
    if (o->operator_name) snprintf(j->operator_name, sizeof j->operator_name, "%s", o->operator_name);
    return launch(j, worker_drive);
}

fg_status fg_job_start_files(fg_job *j, const char *const *paths, int n, const fg_file_opts *o)
{
    int i;
    if (!j || !paths || n <= 0 || !o) return FG_ERR_INVALID;
    j->paths = (char **)fg_xcalloc((size_t)n, sizeof *j->paths);
    if (!j->paths) return FG_ERR_NOMEM;
    for (i = 0; i < n; i++) j->paths[i] = fg_strdup(paths[i]);
    j->npaths = n;
    j->fopts = *o;
    if (o->case_id) snprintf(j->case_id, sizeof j->case_id, "%s", o->case_id);
    if (o->operator_name) snprintf(j->operator_name, sizeof j->operator_name, "%s", o->operator_name);
    snprintf(j->target, sizeof j->target, "%s%s", paths[0], n > 1 ? " (+more)" : "");
    return launch(j, worker_files);
}

fg_status fg_job_start_freespace(fg_job *j, const char *volume, fg_method m)
{
    if (!j || !volume) return FG_ERR_INVALID;
    snprintf(j->target, sizeof j->target, "%s", volume);
    j->method = m;
    return launch(j, worker_freespace);
}

fg_status fg_job_start_scan(fg_job *j, const char *source, const fg_scan_opts *o)
{
    if (!j || !source || !o) return FG_ERR_INVALID;
    snprintf(j->target, sizeof j->target, "%s", source);
    j->sopts = *o;
    if (o->out_dir) snprintf(j->out_dir, sizeof j->out_dir, "%s", o->out_dir);
    if (o->types) snprintf(j->types, sizeof j->types, "%s", o->types);
    if (o->case_id) snprintf(j->case_id, sizeof j->case_id, "%s", o->case_id);
    if (o->operator_name) snprintf(j->operator_name, sizeof j->operator_name, "%s", o->operator_name);
    return launch(j, worker_scan);
}

/* ---- serialisation ------------------------------------------------------- */
static const char *state_name(fg_job_state s)
{
    switch (s) {
    case FG_JOB_RUNNING:   return "running";
    case FG_JOB_DONE:      return "done";
    case FG_JOB_FAILED:    return "failed";
    case FG_JOB_CANCELLED: return "cancelled";
    default:               return "idle";
    }
}

static const char *kind_name(fg_job_kind k)
{
    switch (k) {
    case FG_JOB_DRIVE_ERASE: return "drive-erase";
    case FG_JOB_FILE_ERASE:  return "file-erase";
    case FG_JOB_FREESPACE:   return "freespace";
    case FG_JOB_SCAN:        return "recover";
    }
    return "job";
}

static void one_job_json(fg_jw *w, const fg_job *j)
{
    double now = (double)fg_now_ms();
    fg_jw_obj(w);
    fg_jw_kstr(w, "id", j->id);
    fg_jw_kstr(w, "kind", kind_name(j->kind));
    fg_jw_kstr(w, "title", j->title);
    fg_jw_kstr(w, "target", j->target);
    fg_jw_kstr(w, "state", state_name(j->state));
    fg_jw_kstr(w, "phase", j->phase);
    fg_jw_kstr(w, "detail", j->detail);
    fg_jw_ku64(w, "done", j->done);
    fg_jw_ku64(w, "total", j->total);
    fg_jw_kdbl(w, "percent", j->total ? (double)j->done * 100.0 / (double)j->total : 0.0);
    fg_jw_kdbl(w, "elapsed_seconds",
               ((j->finished_ms ? j->finished_ms : now) - j->started_ms) / 1000.0);
    fg_jw_kstr(w, "message", j->message);
    fg_jw_ki64(w, "status", j->status);

    if (j->has_result) {
        fg_jw_key(w, "result");
        fg_jw_obj(w);
        switch (j->kind) {
        case FG_JOB_DRIVE_ERASE:
            fg_jw_kstr(w, "report_id", j->dres.report_id);
            fg_jw_kstr(w, "method", j->dres.method_name);
            fg_jw_kstr(w, "standard", j->dres.standard);
            fg_jw_ku64(w, "bytes_written", j->dres.bytes_written);
            fg_jw_kbool(w, "verified", j->dres.verify.passed);
            fg_jw_kdbl(w, "verify_coverage", j->dres.verify.coverage_percent);
            fg_jw_kdbl(w, "throughput_mib_s", j->dres.throughput_mbs);
            fg_jw_kbool(w, "firmware_used", j->dres.firmware_used);
            break;
        case FG_JOB_FILE_ERASE:
            fg_jw_kstr(w, "report_id", j->fres.report_id);
            fg_jw_ku64(w, "files_erased", j->fres.files_erased);
            fg_jw_ku64(w, "files_failed", j->fres.files_failed);
            fg_jw_ku64(w, "bytes_erased", j->fres.bytes_erased);
            fg_jw_ku64(w, "slack_bytes", j->fres.slack_bytes);
            fg_jw_ku64(w, "streams_removed", j->fres.streams_removed);
            break;
        case FG_JOB_FREESPACE:
            fg_jw_ku64(w, "bytes_written", j->wres.bytes_written);
            fg_jw_ku64(w, "mft_records_wiped", j->wres.mft_records_wiped);
            fg_jw_kdbl(w, "free_before_gb", j->wres.free_before_gb);
            fg_jw_kdbl(w, "free_after_gb", j->wres.free_after_gb);
            break;
        case FG_JOB_SCAN: {
            const fg_recovered *f;
            int n = 0, i;
            fg_jw_kstr(w, "report_id", j->sres.report_id);
            fg_jw_kstr(w, "filesystem", j->sres.fs_detected);
            fg_jw_ku64(w, "files_recovered", j->sres.files_recovered);
            fg_jw_ku64(w, "bytes_recovered", j->sres.bytes_recovered);
            fg_jw_ku64(w, "headers_seen", j->sres.headers_seen);
            fg_jw_ku64(w, "metadata_recovered", j->sres.metadata_recovered);
            fg_jw_ku64(w, "fragmented", j->sres.fragmented_recovered);
            fg_jw_ku64(w, "rejected", j->sres.rejected_low_confidence);
            fg_jw_kdbl(w, "throughput_mib_s", j->sres.throughput_mbs);
            fg_jw_key(w, "by_category");
            fg_jw_obj(w);
            for (i = 0; i < FG_CAT__COUNT; i++)
                if (j->sres.per_category[i])
                    fg_jw_ku64(w, fg_category_name((fg_category)i), j->sres.per_category[i]);
            fg_jw_obj_end(w);
            fg_jw_key(w, "files");
            fg_jw_arr(w);
            for (f = j->sres.files; f && n < 500; f = f->next, n++) {
                fg_jw_obj(w);
                fg_jw_ku64(w, "index", f->index);
                fg_jw_kstr(w, "name", f->name);
                fg_jw_kstr(w, "type", f->ext ? f->ext : "");
                fg_jw_kstr(w, "category", fg_category_name(f->category));
                fg_jw_kstr(w, "method", fg_rec_method_name(f->method));
                fg_jw_ku64(w, "offset", f->src_offset);
                fg_jw_ku64(w, "size", f->size);
                fg_jw_ki64(w, "confidence", f->confidence);
                fg_jw_kstr(w, "why", f->confidence_why);
                fg_jw_kstr(w, "sha256", f->sha256);
                fg_jw_kstr(w, "path", f->out_path);
                fg_jw_obj_end(w);
            }
            fg_jw_arr_end(w);
            break;
        }
        }
        fg_jw_obj_end(w);
    }
    fg_jw_obj_end(w);
}

void fg_jobs_to_json(const char *id, fg_buf *out)
{
    fg_jw w;
    int i;
    fg_jw_init(&w, 0);
    fg_mutex_lock(g_lock);
    if (id) {
        fg_job *j = fg_job_find(id);
        if (j) one_job_json(&w, j);
        else { fg_jw_obj(&w); fg_jw_kstr(&w, "error", "no such job"); fg_jw_obj_end(&w); }
    } else {
        fg_jw_arr(&w);
        for (i = 0; i < MAX_JOBS; i++)
            if (g_jobs[i].used) one_job_json(&w, &g_jobs[i]);
        fg_jw_arr_end(&w);
    }
    fg_mutex_unlock(g_lock);
    fg_buf_puts(out, fg_jw_text(&w));
    fg_jw_free(&w);
}

/* Report rendering for a finished job, used by GET /api/jobs/<id>/report. */
fg_status fg_job_report(const fg_job *j, fg_report_fmt fmt, const fg_report_meta *m,
                        fg_buf *out);
fg_status fg_job_report(const fg_job *j, fg_report_fmt fmt, const fg_report_meta *m,
                        fg_buf *out)
{
    if (!j || !j->has_result) return FG_ERR_NOTFOUND;
    switch (j->kind) {
    case FG_JOB_DRIVE_ERASE: return fg_report_drive_buf(&j->dres, m, fmt, out);
    case FG_JOB_FILE_ERASE:  return fg_report_files_buf(&j->fres, m, fmt, out);
    case FG_JOB_SCAN:        return fg_report_scan_buf(&j->sres, m, fmt, out);
    default:                 return FG_ERR_UNSUPPORTED;
    }
}
