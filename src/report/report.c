
#include "forge/fg_audit.h"
#include "forge/fg_json.h"
#include "forge/fg_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static void meta_json(fg_jw *w, const fg_report_meta *m)
{
    char host[128], user[128], os[160];
    fg_hostname(host, sizeof host);
    fg_username(user, sizeof user);
    fg_os_describe(os, sizeof os);
    fg_jw_key(w, "report_metadata");
    fg_jw_obj(w);
    fg_jw_kstr(w, "product", FG_PRODUCT " " FG_VERSION_STR);
    fg_jw_kstr(w, "case_id", m && m->case_id ? m->case_id : "");
    fg_jw_kstr(w, "operator", m && m->operator_name ? m->operator_name : user);
    fg_jw_kstr(w, "organisation", m && m->organisation ? m->organisation : "");
    fg_jw_kstr(w, "workstation", host);
    fg_jw_kstr(w, "operating_system", os);
    fg_jw_kstr(w, "session_id", m && m->session_id ? m->session_id : "");
    fg_jw_kstr(w, "audit_log", m && m->audit_log_path ? m->audit_log_path : "");
    fg_jw_kstr(w, "audit_head_hash", m && m->audit_head_hash ? m->audit_head_hash : "");
    fg_jw_kstr(w, "notes", m && m->notes ? m->notes : "");
    fg_jw_obj_end(w);
}


static void html_head(fg_buf *b, const char *title)
{
    fg_buf_printf(b,
"<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>%s</title><style>"
":root{--bg:#f6f7f9;--card:#fff;--ink:#14171c;--muted:#5b6472;--line:#e3e6ea;"
"--ok:#1a7f4b;--bad:#b3261e;--warn:#9a6700;--accent:#1d4ed8}"
"@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a20;--ink:#e8eaed;"
"--muted:#9aa3b0;--line:#2a2f38;--ok:#4ade80;--bad:#f87171;--warn:#fbbf24;--accent:#60a5fa}}"
"*{box-sizing:border-box}body{margin:0;padding:24px;background:var(--bg);color:var(--ink);"
"font:15px/1.55 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}"
".wrap{max-width:1000px;margin:0 auto}"
"header{border-bottom:2px solid var(--accent);padding-bottom:14px;margin-bottom:22px}"
"h1{margin:0 0 4px;font-size:22px;letter-spacing:-.01em}"
"h2{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);"
"margin:26px 0 10px}"
".sub{color:var(--muted);font-size:13px}"
".card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px}"
"table{width:100%%;border-collapse:collapse;font-size:13px}"
"th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}"
"th{color:var(--muted);font-weight:600;white-space:nowrap}"
"td.mono,th.mono{font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:12px;word-break:break-all}"
".kv{display:grid;grid-template-columns:200px 1fr;gap:6px 14px;font-size:13px}"
".kv dt{color:var(--muted)}.kv dd{margin:0;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}"
".badge{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:600}"
".ok{background:color-mix(in srgb,var(--ok) 15%%,transparent);color:var(--ok)}"
".bad{background:color-mix(in srgb,var(--bad) 15%%,transparent);color:var(--bad)}"
".warn{background:color-mix(in srgb,var(--warn) 18%%,transparent);color:var(--warn)}"
".bar{height:6px;border-radius:3px;background:var(--line);overflow:hidden;min-width:60px}"
".bar>i{display:block;height:100%%;background:var(--accent)}"
"footer{margin-top:28px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}"
"@media print{body{background:#fff}.card{break-inside:avoid}}"
"</style></head><body><div class=\"wrap\">", title);
}

static void html_meta_block(fg_buf *b, const fg_report_meta *m)
{
    char host[128], user[128], os[160], ts[32];
    fg_hostname(host, sizeof host);
    fg_username(user, sizeof user);
    fg_os_describe(os, sizeof os);
    fg_iso8601_utc(ts, sizeof ts);
    fg_buf_puts(b, "<h2>Chain of custody</h2><div class=\"card\"><dl class=\"kv\">");
    fg_buf_printf(b, "<dt>Case identifier</dt><dd>%s</dd>",
                  m && m->case_id && *m->case_id ? m->case_id : "&mdash;");
    fg_buf_printf(b, "<dt>Operator</dt><dd>%s</dd>",
                  m && m->operator_name && *m->operator_name ? m->operator_name : user);
    fg_buf_printf(b, "<dt>Organisation</dt><dd>%s</dd>",
                  m && m->organisation && *m->organisation ? m->organisation : "&mdash;");
    fg_buf_printf(b, "<dt>Workstation</dt><dd>%s</dd>", host);
    fg_buf_printf(b, "<dt>Platform</dt><dd>%s</dd>", os);
    fg_buf_printf(b, "<dt>Tool</dt><dd>%s %s</dd>", FG_PRODUCT, FG_VERSION_STR);
    fg_buf_printf(b, "<dt>Report generated</dt><dd>%s</dd>", ts);
    if (m && m->session_id && *m->session_id)
        fg_buf_printf(b, "<dt>Audit session</dt><dd>%s</dd>", m->session_id);
    if (m && m->audit_head_hash && *m->audit_head_hash)
        fg_buf_printf(b, "<dt>Audit chain head (SHA-256)</dt><dd>%s</dd>", m->audit_head_hash);
    if (m && m->notes && *m->notes)
        fg_buf_printf(b, "<dt>Notes</dt><dd>%s</dd>", m->notes);
    fg_buf_puts(b, "</dl></div>");
}

static void html_foot(fg_buf *b)
{
    fg_buf_printf(b,
"<footer>Produced by %s %s &mdash; %s. This report is generated directly from "
"the operation log; the audit chain hash above can be re-verified with "
"<code>forge audit verify</code>.</footer></div></body></html>\n",
        FG_PRODUCT, FG_VERSION_STR, FG_TAGLINE);
}

/* ========================================================================== */
/*  drive erasure report                                                      */
/* ========================================================================== */
fg_status fg_report_drive_buf(const fg_drive_result *r, const fg_report_meta *m,
                              fg_report_fmt fmt, fg_buf *out)
{
    if (!r || !out) return FG_ERR_INVALID;
    fg_buf_init(out);

    if (fmt == FG_RPT_JSON) {
        fg_jw w;
        fg_jw_init(&w, 1);
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "report_type", "drive_erasure_certificate");
        fg_jw_kstr(&w, "report_id", r->report_id);
        meta_json(&w, m);
        fg_jw_key(&w, "device");
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "id", r->device_id);
        fg_jw_kstr(&w, "model", r->model);
        fg_jw_kstr(&w, "serial", r->serial);
        fg_jw_ku64(&w, "capacity_bytes", r->size_bytes);
        fg_jw_ku64(&w, "sector_size", r->sector_size);
        fg_jw_obj_end(&w);
        fg_jw_key(&w, "sanitization");
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "method", r->method_name);
        fg_jw_kstr(&w, "standard", r->standard);
        fg_jw_ki64(&w, "passes_completed", r->passes_done);
        fg_jw_ki64(&w, "passes_total", r->passes_total);
        fg_jw_ku64(&w, "bytes_written", r->bytes_written);
        fg_jw_kbool(&w, "firmware_assisted", r->firmware_used);
        fg_jw_kstr(&w, "firmware_detail", r->firmware_detail);
        fg_jw_ku64(&w, "unwritable_sectors", r->bad_sectors);
        fg_jw_kdbl(&w, "elapsed_seconds", r->seconds);
        fg_jw_kdbl(&w, "throughput_mib_s", r->throughput_mbs);
        fg_jw_kstr(&w, "started_at", r->started_at);
        fg_jw_kstr(&w, "finished_at", r->finished_at);
        fg_jw_obj_end(&w);
        fg_jw_key(&w, "verification");
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "mode", r->verify.mode == FG_VERIFY_FULL ? "full" :
                              r->verify.mode == FG_VERIFY_SAMPLE ? "statistical-sample" : "none");
        fg_jw_kbool(&w, "passed", r->verify.passed);
        fg_jw_ku64(&w, "bytes_checked", r->verify.bytes_checked);
        fg_jw_kdbl(&w, "coverage_percent", r->verify.coverage_percent);
        fg_jw_ku64(&w, "mismatching_bytes", r->verify.mismatches);
        fg_jw_kdbl(&w, "entropy_bits_per_byte", r->verify.entropy);
        fg_jw_kstr(&w, "sample_digest_sha256", r->verify.digest_hex);
        fg_jw_obj_end(&w);
        fg_jw_ki64(&w, "status_code", r->status);
        fg_jw_kstr(&w, "status_text", fg_strerror(r->status));
        fg_jw_kstr(&w, "message", r->message);
        fg_jw_obj_end(&w);
        fg_buf_puts(out, fg_jw_text(&w));
        fg_buf_puts(out, "\n");
        fg_jw_free(&w);
        return FG_OK;
    }

    if (fmt == FG_RPT_CSV) {
        fg_buf_puts(out, "report_id,device,model,serial,capacity_bytes,method,standard,"
                         "passes_done,passes_total,bytes_written,bad_sectors,firmware,"
                         "verify_mode,verify_passed,verify_coverage_pct,mismatches,"
                         "seconds,throughput_mib_s,status,message\n");
        fg_buf_printf(out,
            "%s,%s,\"%s\",\"%s\",%llu,\"%s\",\"%s\",%d,%d,%llu,%llu,%d,%s,%d,%.4f,%llu,"
            "%.2f,%.2f,%d,\"%s\"\n",
            r->report_id, r->device_id, r->model, r->serial,
            (unsigned long long)r->size_bytes, r->method_name, r->standard,
            r->passes_done, r->passes_total, (unsigned long long)r->bytes_written,
            (unsigned long long)r->bad_sectors, r->firmware_used,
            r->verify.mode == FG_VERIFY_FULL ? "full" :
            r->verify.mode == FG_VERIFY_SAMPLE ? "sample" : "none",
            r->verify.passed, r->verify.coverage_percent,
            (unsigned long long)r->verify.mismatches,
            r->seconds, r->throughput_mbs, (int)r->status, r->message);
        return FG_OK;
    }

    if (fmt == FG_RPT_TEXT) {
        char cap[32], thr[32], dur[32];
        fg_human_size(r->size_bytes, cap, sizeof cap);
        fg_human_size((uint64_t)(r->throughput_mbs * 1024 * 1024), thr, sizeof thr);
        fg_human_duration(r->seconds, dur, sizeof dur);
        fg_buf_printf(out,
"CERTIFICATE OF SANITIZATION\n"
"===========================\n"
"Report ID      : %s\n"
"Device         : %s  (%s)\n"
"Serial         : %s\n"
"Capacity       : %s (%llu bytes, %u-byte sectors)\n"
"Method         : %s\n"
"Standard       : %s\n"
"Passes         : %d of %d%s\n"
"Bytes written  : %llu\n"
"Unwritable     : %llu sector(s)\n"
"Duration       : %s  (%s/s)\n"
"Started        : %s\n"
"Finished       : %s\n"
"Verification   : %s, %.4f%% coverage, %llu mismatching byte(s), entropy %.3f b/B\n"
"Result         : %s - %s\n",
            r->report_id, r->device_id, r->model, r->serial[0] ? r->serial : "(none)",
            cap, (unsigned long long)r->size_bytes, r->sector_size,
            r->method_name, r->standard, r->passes_done, r->passes_total,
            r->firmware_used ? " (firmware assisted)" : "",
            (unsigned long long)r->bytes_written, (unsigned long long)r->bad_sectors,
            dur, thr, r->started_at, r->finished_at,
            r->verify.mode == FG_VERIFY_FULL ? "full read-back" :
            r->verify.mode == FG_VERIFY_SAMPLE ? "statistical sample" : "not performed",
            r->verify.coverage_percent, (unsigned long long)r->verify.mismatches,
            r->verify.entropy,
            r->status == FG_OK ? "PASS" : "FAIL", r->message);
        return FG_OK;
    }

    /* HTML certificate */
    {
        char cap[32], dur[32];
        int ok = (r->status == FG_OK);
        fg_human_size(r->size_bytes, cap, sizeof cap);
        fg_human_duration(r->seconds, dur, sizeof dur);
        html_head(out, "Certificate of Sanitization");
        fg_buf_printf(out,
            "<header><h1>Certificate of Sanitization</h1>"
            "<div class=\"sub\">Report %s &middot; generated by %s %s</div></header>",
            r->report_id, FG_PRODUCT, FG_VERSION_STR);
        fg_buf_printf(out, "<div class=\"card\"><span class=\"badge %s\">%s</span> %s</div>",
                      ok ? "ok" : "bad", ok ? "SANITIZED" : "FAILED", r->message);

        fg_buf_puts(out, "<h2>Storage device</h2><div class=\"card\"><dl class=\"kv\">");
        fg_buf_printf(out, "<dt>Device path</dt><dd>%s</dd>", r->device_id);
        fg_buf_printf(out, "<dt>Model</dt><dd>%s</dd>", r->model);
        fg_buf_printf(out, "<dt>Serial number</dt><dd>%s</dd>",
                      r->serial[0] ? r->serial : "&mdash;");
        fg_buf_printf(out, "<dt>Capacity</dt><dd>%s (%llu bytes)</dd>", cap,
                      (unsigned long long)r->size_bytes);
        fg_buf_printf(out, "<dt>Logical sector size</dt><dd>%u bytes</dd>", r->sector_size);
        fg_buf_puts(out, "</dl></div>");

        fg_buf_puts(out, "<h2>Sanitization</h2><div class=\"card\"><dl class=\"kv\">");
        fg_buf_printf(out, "<dt>Method</dt><dd>%s</dd>", r->method_name);
        fg_buf_printf(out, "<dt>Standard</dt><dd>%s</dd>", r->standard);
        fg_buf_printf(out, "<dt>Overwrite passes</dt><dd>%d of %d</dd>",
                      r->passes_done, r->passes_total);
        fg_buf_printf(out, "<dt>Firmware sanitize</dt><dd>%s</dd>",
                      r->firmware_used ? r->firmware_detail : "not used");
        fg_buf_printf(out, "<dt>Bytes written</dt><dd>%llu</dd>",
                      (unsigned long long)r->bytes_written);
        fg_buf_printf(out, "<dt>Unwritable sectors</dt><dd>%llu%s</dd>",
                      (unsigned long long)r->bad_sectors,
                      r->bad_sectors ? " (see remarks)" : "");
        fg_buf_printf(out, "<dt>Elapsed</dt><dd>%s at %.1f MiB/s</dd>", dur, r->throughput_mbs);
        fg_buf_printf(out, "<dt>Started (UTC)</dt><dd>%s</dd>", r->started_at);
        fg_buf_printf(out, "<dt>Finished (UTC)</dt><dd>%s</dd>", r->finished_at);
        fg_buf_puts(out, "</dl></div>");

        fg_buf_puts(out, "<h2>Verification</h2><div class=\"card\"><dl class=\"kv\">");
        fg_buf_printf(out, "<dt>Mode</dt><dd>%s</dd>",
                      r->verify.mode == FG_VERIFY_FULL ? "Full read-back of every sector" :
                      r->verify.mode == FG_VERIFY_SAMPLE ? "Statistical sample" : "Not performed");
        fg_buf_printf(out, "<dt>Result</dt><dd><span class=\"badge %s\">%s</span></dd>",
                      r->verify.passed ? "ok" : "bad",
                      r->verify.passed ? "no residual data detected" : "residual data detected");
        fg_buf_printf(out, "<dt>Bytes examined</dt><dd>%llu (%.4f%% of capacity)</dd>",
                      (unsigned long long)r->verify.bytes_checked, r->verify.coverage_percent);
        fg_buf_printf(out, "<dt>Mismatching bytes</dt><dd>%llu</dd>",
                      (unsigned long long)r->verify.mismatches);
        if (r->verify.entropy > 0.0)
            fg_buf_printf(out, "<dt>Sample entropy</dt><dd>%.4f bits/byte "
                               "(8.0 = indistinguishable from random)</dd>", r->verify.entropy);
        fg_buf_printf(out, "<dt>Sample digest</dt><dd>%s</dd>", r->verify.digest_hex);
        fg_buf_puts(out, "</dl></div>");

        if (r->bad_sectors) {
            fg_buf_printf(out,
                "<h2>Remarks</h2><div class=\"card\"><p>%llu sector(s) could not be "
                "written, the first at byte offset %llu. Sectors retired by the drive's "
                "own defect management are not addressable by any host-level overwrite; "
                "for media that must leave a controlled environment, physical "
                "destruction or a firmware Purge is the only complete option.</p></div>",
                (unsigned long long)r->bad_sectors,
                (unsigned long long)r->bad_sector_first);
        }
        html_meta_block(out, m);
        html_foot(out);
        return FG_OK;
    }
}

/* ========================================================================== */
/*  file erasure report                                                       */
/* ========================================================================== */
fg_status fg_report_files_buf(const fg_file_result *r, const fg_report_meta *m,
                              fg_report_fmt fmt, fg_buf *out)
{
    const fg_file_record *rec;
    if (!r || !out) return FG_ERR_INVALID;
    fg_buf_init(out);

    if (fmt == FG_RPT_JSON) {
        fg_jw w;
        fg_jw_init(&w, 1);
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "report_type", "file_erasure_report");
        fg_jw_kstr(&w, "report_id", r->report_id);
        meta_json(&w, m);
        fg_jw_kstr(&w, "method", r->method_name);
        fg_jw_ku64(&w, "files_total", r->files_total);
        fg_jw_ku64(&w, "files_erased", r->files_erased);
        fg_jw_ku64(&w, "files_failed", r->files_failed);
        fg_jw_ku64(&w, "bytes_erased", r->bytes_erased);
        fg_jw_ku64(&w, "slack_bytes_wiped", r->slack_bytes);
        fg_jw_ku64(&w, "alternate_streams_removed", r->streams_removed);
        fg_jw_ku64(&w, "extended_attributes_removed", r->xattrs_removed);
        fg_jw_ku64(&w, "directories_removed", r->dirs_removed);
        fg_jw_kdbl(&w, "elapsed_seconds", r->seconds);
        fg_jw_kstr(&w, "started_at", r->started_at);
        fg_jw_kstr(&w, "finished_at", r->finished_at);
        fg_jw_key(&w, "files");
        fg_jw_arr(&w);
        for (rec = r->records; rec; rec = rec->next) {
            fg_jw_obj(&w);
            fg_jw_kstr(&w, "path", rec->path);
            fg_jw_ku64(&w, "size", rec->size);
            fg_jw_ki64(&w, "passes", rec->passes);
            fg_jw_ki64(&w, "renames", rec->renames);
            fg_jw_ki64(&w, "alternate_streams", rec->alt_streams_removed);
            fg_jw_ki64(&w, "extended_attributes", rec->xattrs_removed);
            fg_jw_ku64(&w, "slack_bytes", rec->slack_bytes);
            fg_jw_kbool(&w, "verified", rec->verified);
            fg_jw_kstr(&w, "result", fg_strerror(rec->status));
            fg_jw_kstr(&w, "message", rec->message);
            fg_jw_obj_end(&w);
        }
        fg_jw_arr_end(&w);
        fg_jw_obj_end(&w);
        fg_buf_puts(out, fg_jw_text(&w));
        fg_buf_puts(out, "\n");
        fg_jw_free(&w);
        return FG_OK;
    }

    if (fmt == FG_RPT_CSV) {
        fg_buf_puts(out, "path,size_bytes,passes,renames,alt_streams,xattrs,slack_bytes,"
                         "verified,status,message\n");
        for (rec = r->records; rec; rec = rec->next)
            fg_buf_printf(out, "\"%s\",%llu,%d,%d,%d,%d,%llu,%d,%d,\"%s\"\n",
                          rec->path, (unsigned long long)rec->size, rec->passes,
                          rec->renames, rec->alt_streams_removed, rec->xattrs_removed,
                          (unsigned long long)rec->slack_bytes, rec->verified,
                          (int)rec->status, rec->message);
        return FG_OK;
    }

    if (fmt == FG_RPT_TEXT) {
        char sz[32];
        fg_human_size(r->bytes_erased, sz, sizeof sz);
        fg_buf_printf(out,
"FILE AND FOLDER ERASURE REPORT\n"
"==============================\n"
"Report ID    : %s\n"
"Method       : %s\n"
"Files erased : %llu of %llu  (%llu failed)\n"
"Data erased  : %s\n"
"Slack wiped  : %llu bytes\n"
"ADS removed  : %llu    xattrs removed: %llu\n"
"Directories  : %llu removed\n"
"Elapsed      : %.2f s\n",
            r->report_id, r->method_name,
            (unsigned long long)r->files_erased, (unsigned long long)r->files_total,
            (unsigned long long)r->files_failed, sz,
            (unsigned long long)r->slack_bytes,
            (unsigned long long)r->streams_removed,
            (unsigned long long)r->xattrs_removed,
            (unsigned long long)r->dirs_removed, r->seconds);
        return FG_OK;
    }

    {
        char sz[32];
        fg_human_size(r->bytes_erased, sz, sizeof sz);
        html_head(out, "File and Folder Erasure Report");
        fg_buf_printf(out,
            "<header><h1>File and Folder Erasure Report</h1>"
            "<div class=\"sub\">Report %s &middot; %s</div></header>",
            r->report_id, r->method_name);
        fg_buf_printf(out,
            "<div class=\"card\"><dl class=\"kv\">"
            "<dt>Files erased</dt><dd>%llu of %llu (%llu failed)</dd>"
            "<dt>Data destroyed</dt><dd>%s</dd>"
            "<dt>Cluster slack wiped</dt><dd>%llu bytes</dd>"
            "<dt>Alternate data streams removed</dt><dd>%llu</dd>"
            "<dt>Extended attributes removed</dt><dd>%llu</dd>"
            "<dt>Directories removed</dt><dd>%llu</dd>"
            "<dt>Elapsed</dt><dd>%.2f s</dd>"
            "<dt>Started (UTC)</dt><dd>%s</dd>"
            "<dt>Finished (UTC)</dt><dd>%s</dd>"
            "</dl></div>",
            (unsigned long long)r->files_erased, (unsigned long long)r->files_total,
            (unsigned long long)r->files_failed, sz,
            (unsigned long long)r->slack_bytes, (unsigned long long)r->streams_removed,
            (unsigned long long)r->xattrs_removed, (unsigned long long)r->dirs_removed,
            r->seconds, r->started_at, r->finished_at);

        fg_buf_puts(out, "<h2>Per-file detail</h2><div class=\"card\"><table>"
                         "<tr><th>Path</th><th>Size</th><th>Passes</th><th>Renames</th>"
                         "<th>ADS</th><th>xattr</th><th>Slack</th><th>Verified</th>"
                         "<th>Result</th></tr>");
        for (rec = r->records; rec; rec = rec->next) {
            char s2[32];
            fg_human_size(rec->size, s2, sizeof s2);
            fg_buf_printf(out,
                "<tr><td class=\"mono\">%s</td><td>%s</td><td>%d</td><td>%d</td>"
                "<td>%d</td><td>%d</td><td>%llu</td>"
                "<td><span class=\"badge %s\">%s</span></td><td>%s</td></tr>",
                rec->path, s2, rec->passes, rec->renames,
                rec->alt_streams_removed, rec->xattrs_removed,
                (unsigned long long)rec->slack_bytes,
                rec->verified ? "ok" : "warn", rec->verified ? "yes" : "no",
                rec->status == FG_OK ? "erased" : fg_strerror(rec->status));
        }
        fg_buf_puts(out, "</table></div>");
        html_meta_block(out, m);
        html_foot(out);
        return FG_OK;
    }
}

/* ========================================================================== */
/*  recovery report                                                           */
/* ========================================================================== */
static const char *conf_class(int c)
{
    return c >= 75 ? "ok" : c >= 45 ? "warn" : "bad";
}

fg_status fg_report_scan_buf(const fg_scan_result *r, const fg_report_meta *m,
                             fg_report_fmt fmt, fg_buf *out)
{
    const fg_recovered *f;
    int i;
    if (!r || !out) return FG_ERR_INVALID;
    fg_buf_init(out);

    if (fmt == FG_RPT_JSON) {
        fg_jw w;
        fg_jw_init(&w, 1);
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "report_type", "forensic_recovery_report");
        fg_jw_kstr(&w, "report_id", r->report_id);
        meta_json(&w, m);
        fg_jw_key(&w, "source");
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "path", r->source);
        fg_jw_ku64(&w, "size_bytes", r->source_size);
        fg_jw_kstr(&w, "filesystem", r->fs_detected);
        fg_jw_kstr(&w, "acquisition_hash_sha256", r->source_sha256);
        fg_jw_kbool(&w, "opened_read_only", 1);
        fg_jw_obj_end(&w);
        fg_jw_key(&w, "statistics");
        fg_jw_obj(&w);
        fg_jw_ku64(&w, "bytes_scanned", r->bytes_scanned);
        fg_jw_ku64(&w, "headers_seen", r->headers_seen);
        fg_jw_ku64(&w, "files_recovered", r->files_recovered);
        fg_jw_ku64(&w, "bytes_recovered", r->bytes_recovered);
        fg_jw_ku64(&w, "recovered_via_metadata", r->metadata_recovered);
        fg_jw_ku64(&w, "recovered_via_fragment_reassembly", r->fragmented_recovered);
        fg_jw_ku64(&w, "rejected_low_confidence", r->rejected_low_confidence);
        fg_jw_kdbl(&w, "elapsed_seconds", r->seconds);
        fg_jw_kdbl(&w, "throughput_mib_s", r->throughput_mbs);
        fg_jw_key(&w, "by_category");
        fg_jw_obj(&w);
        for (i = 0; i < FG_CAT__COUNT; i++)
            if (r->per_category[i])
                fg_jw_ku64(&w, fg_category_name((fg_category)i), r->per_category[i]);
        fg_jw_obj_end(&w);
        fg_jw_obj_end(&w);
        fg_jw_key(&w, "recovered_files");
        fg_jw_arr(&w);
        for (f = r->files; f; f = f->next) {
            fg_jw_obj(&w);
            fg_jw_ku64(&w, "index", f->index);
            fg_jw_kstr(&w, "name", f->name);
            fg_jw_kstr(&w, "output_path", f->out_path);
            fg_jw_kstr(&w, "type", f->ext ? f->ext : "");
            fg_jw_kstr(&w, "category", fg_category_name(f->category));
            fg_jw_kstr(&w, "recovery_method", fg_rec_method_name(f->method));
            fg_jw_ku64(&w, "source_offset", f->src_offset);
            fg_jw_ku64(&w, "size", f->size);
            fg_jw_ki64(&w, "fragments", f->fragments);
            fg_jw_ki64(&w, "confidence", f->confidence);
            fg_jw_kstr(&w, "confidence_basis", f->confidence_why);
            fg_jw_kbool(&w, "header_valid", f->header_ok);
            fg_jw_kbool(&w, "footer_found", f->footer_ok);
            fg_jw_kbool(&w, "structure_validated", f->structure_ok);
            fg_jw_kbool(&w, "checksum_verified", f->checksum_ok);
            fg_jw_kdbl(&w, "entropy", f->entropy);
            fg_jw_kstr(&w, "sha256", f->sha256);
            fg_jw_kstr(&w, "md5", f->md5);
            if (f->mtime) {
                char ts[32];
                fg_iso8601_from_unix(f->mtime, ts, sizeof ts);
                fg_jw_kstr(&w, "original_mtime", ts);
            }
            fg_jw_kbool(&w, "marked_deleted", f->deleted_flag);
            fg_jw_ki64(&w, "overwrite_risk_percent", f->overwritten_risk);
            if (f->fragments > 1) {
                int k;
                fg_jw_key(&w, "extents");
                fg_jw_arr(&w);
                for (k = 0; k < f->fragments && k < 8; k++) {
                    fg_jw_obj(&w);
                    fg_jw_ku64(&w, "offset", f->frag_off[k]);
                    fg_jw_ku64(&w, "length", f->frag_len[k]);
                    fg_jw_obj_end(&w);
                }
                fg_jw_arr_end(&w);
            }
            fg_jw_obj_end(&w);
        }
        fg_jw_arr_end(&w);
        fg_jw_obj_end(&w);
        fg_buf_puts(out, fg_jw_text(&w));
        fg_buf_puts(out, "\n");
        fg_jw_free(&w);
        return FG_OK;
    }

    if (fmt == FG_RPT_CSV) {
        fg_buf_puts(out, "index,name,type,category,method,source_offset,size,fragments,"
                         "confidence,header_ok,footer_ok,structure_ok,checksum_ok,"
                         "entropy,sha256,md5,output_path\n");
        for (f = r->files; f; f = f->next)
            fg_buf_printf(out, "%u,\"%s\",%s,%s,\"%s\",%llu,%llu,%d,%d,%d,%d,%d,%d,"
                               "%.4f,%s,%s,\"%s\"\n",
                          f->index, f->name, f->ext ? f->ext : "",
                          fg_category_name(f->category), fg_rec_method_name(f->method),
                          (unsigned long long)f->src_offset, (unsigned long long)f->size,
                          f->fragments, f->confidence, f->header_ok, f->footer_ok,
                          f->structure_ok, f->checksum_ok, f->entropy,
                          f->sha256, f->md5, f->out_path);
        return FG_OK;
    }

    if (fmt == FG_RPT_TEXT) {
        char sz[32];
        fg_human_size(r->bytes_recovered, sz, sizeof sz);
        fg_buf_printf(out,
"FORENSIC RECOVERY REPORT\n"
"========================\n"
"Report ID   : %s\n"
"Source      : %s (%llu bytes, %s)\n"
"Scanned     : %llu bytes in %.2f s (%.1f MiB/s)\n"
"Headers     : %llu candidate signatures\n"
"Recovered   : %llu files, %s\n"
"  metadata  : %llu\n  fragmented: %llu\n  rejected  : %llu below confidence floor\n\n",
            r->report_id, r->source, (unsigned long long)r->source_size,
            r->fs_detected, (unsigned long long)r->bytes_scanned, r->seconds,
            r->throughput_mbs, (unsigned long long)r->headers_seen,
            (unsigned long long)r->files_recovered, sz,
            (unsigned long long)r->metadata_recovered,
            (unsigned long long)r->fragmented_recovered,
            (unsigned long long)r->rejected_low_confidence);
        for (f = r->files; f; f = f->next) {
            char s2[32];
            fg_human_size(f->size, s2, sizeof s2);
            fg_buf_printf(out, "[%3d%%] %-38s %-9s %-24s @0x%llx  %s\n",
                          f->confidence, f->name, s2, fg_rec_method_name(f->method),
                          (unsigned long long)f->src_offset, f->sha256);
        }
        return FG_OK;
    }

    {
        char sz[32], src[32];
        fg_human_size(r->bytes_recovered, sz, sizeof sz);
        fg_human_size(r->source_size, src, sizeof src);
        html_head(out, "Forensic Recovery Report");
        fg_buf_printf(out,
            "<header><h1>Forensic Recovery Report</h1>"
            "<div class=\"sub\">Report %s &middot; %s</div></header>",
            r->report_id, r->source);

        fg_buf_printf(out,
            "<div class=\"card\"><dl class=\"kv\">"
            "<dt>Evidence source</dt><dd>%s</dd>"
            "<dt>Source size</dt><dd>%s (%llu bytes)</dd>"
            "<dt>Filesystem</dt><dd>%s</dd>"
            "<dt>Access mode</dt><dd>read-only (software write block)</dd>"
            "<dt>Bytes examined</dt><dd>%llu</dd>"
            "<dt>Candidate signatures</dt><dd>%llu</dd>"
            "<dt>Files recovered</dt><dd>%llu totalling %s</dd>"
            "<dt>Recovered from metadata</dt><dd>%llu</dd>"
            "<dt>Reassembled from fragments</dt><dd>%llu</dd>"
            "<dt>Rejected below confidence floor</dt><dd>%llu</dd>"
            "<dt>Elapsed</dt><dd>%.2f s (%.1f MiB/s)</dd>"
            "<dt>Started (UTC)</dt><dd>%s</dd>"
            "<dt>Finished (UTC)</dt><dd>%s</dd>"
            "</dl></div>",
            r->source, src, (unsigned long long)r->source_size, r->fs_detected,
            (unsigned long long)r->bytes_scanned, (unsigned long long)r->headers_seen,
            (unsigned long long)r->files_recovered, sz,
            (unsigned long long)r->metadata_recovered,
            (unsigned long long)r->fragmented_recovered,
            (unsigned long long)r->rejected_low_confidence,
            r->seconds, r->throughput_mbs, r->started_at, r->finished_at);

        fg_buf_puts(out, "<h2>Recovered content by category</h2><div class=\"card\"><table>"
                         "<tr><th>Category</th><th>Files</th><th></th></tr>");
        {
            uint32_t max = 1;
            for (i = 0; i < FG_CAT__COUNT; i++)
                if (r->per_category[i] > max) max = r->per_category[i];
            for (i = 0; i < FG_CAT__COUNT; i++) {
                if (!r->per_category[i]) continue;
                fg_buf_printf(out,
                    "<tr><td>%s</td><td>%u</td><td><div class=\"bar\">"
                    "<i style=\"width:%u%%\"></i></div></td></tr>",
                    fg_category_name((fg_category)i), r->per_category[i],
                    (unsigned)(r->per_category[i] * 100u / max));
            }
        }
        fg_buf_puts(out, "</table></div>");

        fg_buf_puts(out, "<h2>Recovered files</h2><div class=\"card\"><table>"
                         "<tr><th>#</th><th>Name</th><th>Type</th><th>Size</th>"
                         "<th>Offset</th><th>Method</th><th>Confidence</th>"
                         "<th class=\"mono\">SHA-256</th></tr>");
        for (f = r->files; f; f = f->next) {
            char s2[32];
            fg_human_size(f->size, s2, sizeof s2);
            fg_buf_printf(out,
                "<tr><td>%u</td><td>%s</td><td>%s</td><td>%s</td>"
                "<td class=\"mono\">0x%llx</td><td>%s%s</td>"
                "<td><span class=\"badge %s\" title=\"%s\">%d%%</span></td>"
                "<td class=\"mono\">%s</td></tr>",
                f->index, f->name, f->ext ? f->ext : "?", s2,
                (unsigned long long)f->src_offset, fg_rec_method_name(f->method),
                f->fragments > 1 ? " (fragmented)" : "",
                conf_class(f->confidence), f->confidence_why, f->confidence, f->sha256);
        }
        fg_buf_puts(out, "</table></div>");
        fg_buf_puts(out,
            "<h2>Evidential notes</h2><div class=\"card\"><p>The source was opened "
            "read-only for the entire operation; no write was issued to the evidence "
            "device. Each recovered object is listed with the byte offset it was taken "
            "from and a SHA-256 digest computed at extraction time, so any later copy "
            "can be proven identical. Confidence is derived from independent structural "
            "checks (header, internal length fields, footer, embedded checksums, entropy "
            "profile) - hover a confidence badge to see which checks contributed.</p>"
            "</div>");
        html_meta_block(out, m);
        html_foot(out);
        return FG_OK;
    }
}

/* ========================================================================== */
/*  file writers                                                              */
/* ========================================================================== */
static fg_status dump(fg_buf *b, const char *path)
{
    FILE *f;
    if (!path) { fg_buf_free(b); return FG_ERR_INVALID; }
    f = fopen(path, "wb");
    if (!f) { fg_buf_free(b); return FG_ERR_PERM; }
    if (b->len) fwrite(b->data, 1, b->len, f);
    fclose(f);
    fg_buf_free(b);
    return FG_OK;
}

fg_status fg_report_drive(const fg_drive_result *r, const fg_report_meta *m,
                          fg_report_fmt fmt, const char *out_path)
{
    fg_buf b;
    fg_status st = fg_report_drive_buf(r, m, fmt, &b);
    if (st != FG_OK) return st;
    return dump(&b, out_path);
}

fg_status fg_report_files(const fg_file_result *r, const fg_report_meta *m,
                          fg_report_fmt fmt, const char *out_path)
{
    fg_buf b;
    fg_status st = fg_report_files_buf(r, m, fmt, &b);
    if (st != FG_OK) return st;
    return dump(&b, out_path);
}

fg_status fg_report_scan(const fg_scan_result *r, const fg_report_meta *m,
                         fg_report_fmt fmt, const char *out_path)
{
    fg_buf b;
    fg_status st = fg_report_scan_buf(r, m, fmt, &b);
    if (st != FG_OK) return st;
    return dump(&b, out_path);
}
