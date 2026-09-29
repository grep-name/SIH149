/* fg_ui.h - embedded dashboard: a dependency-free HTTP/1.1 server plus the
 * background job manager the web front-end drives.
 */
#ifndef FG_UI_H
#define FG_UI_H

#include "fg_common.h"
#include "fg_erase.h"
#include "fg_carve.h"
#include "fg_audit.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- job manager --------------------------------------------------------- */
typedef enum {
    FG_JOB_IDLE = 0, FG_JOB_RUNNING, FG_JOB_DONE, FG_JOB_FAILED, FG_JOB_CANCELLED
} fg_job_state;

typedef enum { FG_JOB_DRIVE_ERASE, FG_JOB_FILE_ERASE, FG_JOB_FREESPACE, FG_JOB_SCAN } fg_job_kind;

typedef struct fg_job fg_job;

fg_status   fg_jobs_init(fg_audit *audit);
void        fg_jobs_shutdown(void);

fg_job     *fg_job_create(fg_job_kind kind, const char *title);
const char *fg_job_id(const fg_job *j);
fg_job     *fg_job_find(const char *id);
void        fg_job_cancel(const char *id);
/* Serialise one job, or every job when id is NULL. */
void        fg_jobs_to_json(const char *id, fg_buf *out);

/* Start a job in the background. Options are copied. */
fg_status fg_job_start_drive(fg_job *j, const char *device, const fg_drive_opts *o);
fg_status fg_job_start_files(fg_job *j, const char *const *paths, int n,
                             const fg_file_opts *o);
fg_status fg_job_start_freespace(fg_job *j, const char *volume, fg_method m);
fg_status fg_job_start_scan(fg_job *j, const char *source, const fg_scan_opts *o);

/* ---- HTTP server --------------------------------------------------------- */
typedef struct {
    const char *bind_addr;   /* default 127.0.0.1                             */
    int         port;        /* default 8787                                  */
    const char *token;       /* required in X-Forge-Token; NULL = generate    */
    int         open_browser;
    fg_audit   *audit;
} fg_server_opts;

fg_status fg_server_run(const fg_server_opts *o);   /* blocks until Ctrl-C     */
void      fg_server_stop(void);

/* The dashboard, compiled into the binary by tools/bin2c. */
extern const unsigned char fg_ui_dashboard_html[];
extern const unsigned int  fg_ui_dashboard_html_len;

#ifdef __cplusplus
}
#endif
#endif /* FG_UI_H */
