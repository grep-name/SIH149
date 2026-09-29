/* fg_audit.h - Reporting and Audit Management System.
 *
 * The audit log is an append-only hash chain: record N stores the SHA-256 of
 * (prev_hash || canonical_record_N), so altering or deleting any past record
 * breaks every hash after it. The chain is additionally sealed with an
 * HMAC-SHA256 under a session key so an attacker who can rewrite the whole
 * file still cannot forge a valid seal without the key.
 */
#ifndef FG_AUDIT_H
#define FG_AUDIT_H

#include "fg_common.h"
#include "fg_crypto.h"
#include "fg_erase.h"
#include "fg_carve.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FG_EV_SESSION_START, FG_EV_SESSION_END, FG_EV_DEVICE_ENUM,
    FG_EV_ERASE_BEGIN, FG_EV_ERASE_PASS, FG_EV_ERASE_VERIFY, FG_EV_ERASE_END,
    FG_EV_FILE_ERASE, FG_EV_FREESPACE,
    FG_EV_SCAN_BEGIN, FG_EV_SCAN_FILE, FG_EV_SCAN_END,
    FG_EV_CUSTODY, FG_EV_ERROR, FG_EV_REFUSED
} fg_event;

const char *fg_event_name(fg_event e);

typedef struct fg_audit fg_audit;

/* `key` seals the chain; pass NULL to derive a random session key which is
 * printed once at session start so the operator can archive it separately. */
fg_status fg_audit_open(fg_audit **out, const char *log_path,
                        const uint8_t *key, size_t keylen,
                        const char *operator_name, const char *case_id);
void      fg_audit_close(fg_audit *a);

/* Append one event. `detail_json` must be a JSON object body without the
 * outer braces, or NULL. */
fg_status fg_audit_event(fg_audit *a, fg_event e, fg_status st,
                         const char *subject, const char *detail_json);
fg_status fg_audit_eventf(fg_audit *a, fg_event e, fg_status st,
                          const char *subject, const char *fmt, ...);

const char *fg_audit_session_id(const fg_audit *a);
uint64_t    fg_audit_record_count(const fg_audit *a);
const char *fg_audit_head_hash(const fg_audit *a);

typedef struct {
    uint64_t records;
    uint64_t sessions;           /* a log accumulates one chain per session   */
    uint64_t first_bad_record;   /* 0 when intact                             */
    int      chain_ok;
    int      seal_ok;
    int      seal_checked;
    char     head_hash[65];
    char     message[256];
    char     session_id[33];
    char     started_at[32];
    char     operator_name[96];
    char     case_id[96];
} fg_audit_verify;

/* Re-walk a log file and prove the chain (and, with a key, the seal). */
fg_status fg_audit_verify_file(const char *log_path,
                               const uint8_t *key, size_t keylen,
                               fg_audit_verify *out);

/* ========================================================================== */
/*  Reports                                                                   */
/* ========================================================================== */

typedef enum { FG_RPT_JSON, FG_RPT_HTML, FG_RPT_CSV, FG_RPT_TEXT } fg_report_fmt;

typedef struct {
    const char *case_id;
    const char *operator_name;
    const char *organisation;
    const char *notes;
    const char *audit_log_path;
    const char *audit_head_hash;
    const char *session_id;
} fg_report_meta;

fg_status fg_report_drive(const fg_drive_result *r, const fg_report_meta *m,
                          fg_report_fmt fmt, const char *out_path);
fg_status fg_report_files(const fg_file_result *r, const fg_report_meta *m,
                          fg_report_fmt fmt, const char *out_path);
fg_status fg_report_scan(const fg_scan_result *r, const fg_report_meta *m,
                         fg_report_fmt fmt, const char *out_path);

/* Serialise to a buffer instead of a file (used by the HTTP API). */
fg_status fg_report_drive_buf(const fg_drive_result *r, const fg_report_meta *m,
                              fg_report_fmt fmt, fg_buf *out);
fg_status fg_report_scan_buf(const fg_scan_result *r, const fg_report_meta *m,
                             fg_report_fmt fmt, fg_buf *out);
fg_status fg_report_files_buf(const fg_file_result *r, const fg_report_meta *m,
                              fg_report_fmt fmt, fg_buf *out);

/* 32-hex-char random identifier used for report_id / session_id. */
void fg_make_id(char out[33]);

#ifdef __cplusplus
}
#endif
#endif /* FG_AUDIT_H */
