/* kv_ui.h - embedded dashboard: a dependency-free HTTP/1.1 server plus the
 * background job manager the web front-end drives.
 */
#ifndef KV_UI_H
#define KV_UI_H

#include "kv_common.h"
#include "kv_erase.h"
#include "kv_carve.h"
#include "kv_audit.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- job manager --------------------------------------------------------- */
typedef enum {
    KV_JOB_IDLE = 0, KV_JOB_RUNNING, KV_JOB_DONE, KV_JOB_FAILED, KV_JOB_CANCELLED
} kv_job_state;

typedef enum { KV_JOB_DRIVE_ERASE, KV_JOB_FILE_ERASE, KV_JOB_FREESPACE, KV_JOB_SCAN } kv_job_kind;

typedef struct kv_job kv_job;

kv_status   kv_jobs_init(kv_audit *audit);
void        kv_jobs_shutdown(void);

kv_job     *kv_job_create(kv_job_kind kind, const char *title);
const char *kv_job_id(const kv_job *j);
kv_job     *kv_job_find(const char *id);
void        kv_job_cancel(const char *id);
/* Serialise one job, or every job when id is NULL. */
void        kv_jobs_to_json(const char *id, kv_buf *out);

/* Start a job in the background. Options are copied. */
kv_status kv_job_start_drive(kv_job *j, const char *device, const kv_drive_opts *o);
kv_status kv_job_start_files(kv_job *j, const char *const *paths, int n,
                             const kv_file_opts *o);
kv_status kv_job_start_freespace(kv_job *j, const char *volume, kv_method m);
kv_status kv_job_start_scan(kv_job *j, const char *source, const kv_scan_opts *o);

/* ---- HTTP server --------------------------------------------------------- */
typedef struct {
    const char *bind_addr;   /* default 127.0.0.1                             */
    int         port;        /* default 8787                                  */
    const char *token;       /* required in X-Kavach-Token; NULL = generate    */
    int         open_browser;
    kv_audit   *audit;
} kv_server_opts;

kv_status kv_server_run(const kv_server_opts *o);   /* blocks until Ctrl-C     */
void      kv_server_stop(void);

/* The dashboard, compiled into the binary by tools/bin2c. */
extern const unsigned char kv_ui_dashboard_html[];
extern const unsigned int  kv_ui_dashboard_html_len;

#ifdef __cplusplus
}
#endif
#endif /* KV_UI_H */
