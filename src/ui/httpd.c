
#include "forge/fg_ui.h"
#include "forge/fg_json.h"
#include "forge/fg_platform.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define REQ_MAX (256 * 1024)

static volatile int g_stop = 0;
static char  g_token[33];
static fg_audit *g_audit_ref;

fg_status fg_job_report(const fg_job *j, fg_report_fmt fmt, const fg_report_meta *m,
                        fg_buf *out);

void fg_server_stop(void) { g_stop = 1; }

/* ---- tiny request model -------------------------------------------------- */
typedef struct {
    char  method[8];
    char  path[1024];
    char  query[1024];
    char  token[128];
    char *body;
    size_t body_len;
} req;

static void url_decode(char *s)
{
    char *o = s;
    while (*s) {
        if (*s == '%' && s[1] && s[2]) {
            int hi = s[1], lo = s[2], v;
            hi = (hi >= '0' && hi <= '9') ? hi - '0' :
                 (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                 (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
            lo = (lo >= '0' && lo <= '9') ? lo - '0' :
                 (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                 (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
            if (hi >= 0 && lo >= 0) { v = hi * 16 + lo; *o++ = (char)v; s += 3; continue; }
        }
        if (*s == '+') { *o++ = ' '; s++; continue; }
        *o++ = *s++;
    }
    *o = '\0';
}

static const char *query_get(const char *query, const char *key, char *out, size_t outsz)
{
    const char *p = query;
    size_t kl = strlen(key);
    out[0] = '\0';
    while (p && *p) {
        const char *amp = strchr(p, '&');
        if (!strncmp(p, key, kl) && p[kl] == '=') {
            size_t n = amp ? (size_t)(amp - p - kl - 1) : strlen(p + kl + 1);
            if (n >= outsz) n = outsz - 1;
            memcpy(out, p + kl + 1, n);
            out[n] = '\0';
            url_decode(out);
            return out;
        }
        if (!amp) break;
        p = amp + 1;
    }
    return NULL;
}

static void send_raw(fg_socket s, const char *status, const char *ctype,
                     const char *body, size_t len)
{
    char hdr[512];
    int n = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %llu\r\n"
        "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
        "Referrer-Policy: no-referrer\r\nConnection: close\r\n\r\n",
        status, ctype, (unsigned long long)len);
    fg_net_send(s, hdr, n);
    if (len) {
        size_t sent = 0;
        while (sent < len) {
            int w = fg_net_send(s, body + sent, (int)FG_MIN(len - sent, (size_t)32768));
            if (w <= 0) break;
            sent += (size_t)w;
        }
    }
}

static void send_json(fg_socket s, const char *status, const char *json)
{
    send_raw(s, status, "application/json; charset=utf-8", json, strlen(json));
}

static void send_err(fg_socket s, const char *status, const char *msg)
{
    fg_buf b;
    fg_buf_init(&b);
    fg_buf_puts(&b, "{\"error\":\"");
    fg_json_escape(&b, msg);
    fg_buf_puts(&b, "\"}");
    send_json(s, status, b.data ? b.data : "{}");
    fg_buf_free(&b);
}

/* ---- API handlers -------------------------------------------------------- */
static void api_devices(fg_socket s)
{
    fg_device_info list[64];
    int n = fg_dev_enumerate(list, 64), i;
    fg_jw w;
    fg_jw_init(&w, 0);
    fg_jw_arr(&w);
    for (i = 0; i < n; i++) {
        char cap[32];
        fg_human_size(list[i].size_bytes, cap, sizeof cap);
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "id", list[i].id);
        fg_jw_kstr(&w, "model", list[i].model);
        fg_jw_kstr(&w, "serial", list[i].serial);
        fg_jw_kstr(&w, "firmware", list[i].firmware);
        fg_jw_ku64(&w, "size_bytes", list[i].size_bytes);
        fg_jw_kstr(&w, "size_human", cap);
        fg_jw_ku64(&w, "sector_size", list[i].logical_sector);
        fg_jw_kstr(&w, "media",
            list[i].media == FG_MEDIA_SSD ? "SSD" :
            list[i].media == FG_MEDIA_HDD ? "HDD" :
            list[i].media == FG_MEDIA_FLASH ? "Flash" :
            list[i].media == FG_MEDIA_OPTICAL ? "Optical" :
            list[i].media == FG_MEDIA_IMAGE ? "Image" : "Unknown");
        fg_jw_kstr(&w, "bus",
            list[i].bus == FG_BUS_NVME ? "NVMe" :
            list[i].bus == FG_BUS_SATA ? "SATA" :
            list[i].bus == FG_BUS_ATA ? "ATA" :
            list[i].bus == FG_BUS_USB ? "USB" :
            list[i].bus == FG_BUS_SCSI ? "SCSI" :
            list[i].bus == FG_BUS_SD ? "SD" :
            list[i].bus == FG_BUS_MMC ? "MMC" :
            list[i].bus == FG_BUS_RAID ? "RAID" :
            list[i].bus == FG_BUS_VIRTUAL ? "Virtual" : "Unknown");
        fg_jw_kbool(&w, "removable", list[i].removable);
        fg_jw_kbool(&w, "system_disk", list[i].is_system);
        fg_jw_kbool(&w, "mounted", list[i].has_mounted_fs);
        fg_jw_kstr(&w, "mountpoints", list[i].mountpoints);
        fg_jw_kbool(&w, "trim", list[i].supports_trim);
        fg_jw_kbool(&w, "ata_secure_erase", list[i].supports_ata_secure_erase);
        fg_jw_kbool(&w, "nvme_sanitize", list[i].supports_nvme_sanitize);
        fg_jw_obj_end(&w);
    }
    fg_jw_arr_end(&w);
    send_json(s, "200 OK", fg_jw_text(&w));
    fg_jw_free(&w);
}

static void emit_method(void *user, const fg_method_def *d)
{
    fg_jw *w = (fg_jw *)user;
    fg_jw_obj(w);
    fg_jw_kstr(w, "id", d->cli_name);
    fg_jw_kstr(w, "name", d->name);
    fg_jw_kstr(w, "standard", d->standard);
    fg_jw_ki64(w, "passes", d->pass_count);
    fg_jw_kbool(w, "firmware_first", d->firmware_first);
    fg_jw_obj_end(w);
}

static void api_methods(fg_socket s)
{
    fg_jw w;
    fg_jw_init(&w, 0);
    fg_jw_arr(&w);
    fg_method_list(emit_method, &w);
    fg_jw_arr_end(&w);
    send_json(s, "200 OK", fg_jw_text(&w));
    fg_jw_free(&w);
}

static void api_signatures(fg_socket s)
{
    int n, i;
    const fg_sig *t = fg_sig_table(&n);
    fg_jw w;
    fg_jw_init(&w, 0);
    fg_jw_arr(&w);
    for (i = 0; i < n; i++) {
        fg_jw_obj(&w);
        fg_jw_kstr(&w, "ext", t[i].ext);
        fg_jw_kstr(&w, "description", t[i].desc);
        fg_jw_kstr(&w, "category", fg_category_name(t[i].category));
        fg_jw_kbool(&w, "structure_aware", t[i].validate != NULL);
        fg_jw_kbool(&w, "has_footer", t[i].footer != NULL);
        fg_jw_obj_end(&w);
    }
    fg_jw_arr_end(&w);
    send_json(s, "200 OK", fg_jw_text(&w));
    fg_jw_free(&w);
}

static void api_system(fg_socket s)
{
    char host[128], user[128], os[192];
    fg_jw w;
    fg_hostname(host, sizeof host);
    fg_username(user, sizeof user);
    fg_os_describe(os, sizeof os);
    fg_jw_init(&w, 0);
    fg_jw_obj(&w);
    fg_jw_kstr(&w, "product", FG_PRODUCT);
    fg_jw_kstr(&w, "version", FG_VERSION_STR);
    fg_jw_kstr(&w, "tagline", FG_TAGLINE);
    fg_jw_kstr(&w, "host", host);
    fg_jw_kstr(&w, "user", user);
    fg_jw_kstr(&w, "os", os);
    fg_jw_kbool(&w, "elevated", fg_is_elevated());
    fg_jw_kstr(&w, "audit_session", g_audit_ref ? fg_audit_session_id(g_audit_ref) : "");
    fg_jw_ku64(&w, "audit_records", g_audit_ref ? fg_audit_record_count(g_audit_ref) : 0);
    fg_jw_kstr(&w, "audit_head", g_audit_ref ? fg_audit_head_hash(g_audit_ref) : "");
    fg_jw_obj_end(&w);
    send_json(s, "200 OK", fg_jw_text(&w));
    fg_jw_free(&w);
}

static fg_method method_from(const fg_jval *o, const char *key, fg_method fb)
{
    const char *m = fg_json_gets(o, key, NULL);
    fg_method r;
    if (!m) return fb;
    r = fg_method_parse(m);
    return (r == (fg_method)-1) ? fb : r;
}

static fg_verify_mode verify_from(const fg_jval *o)
{
    const char *v = fg_json_gets(o, "verify", "sample");
    if (!strcmp(v, "full")) return FG_VERIFY_FULL;
    if (!strcmp(v, "none")) return FG_VERIFY_NONE;
    return FG_VERIFY_SAMPLE;
}

static void reply_job(fg_socket s, fg_job *j, fg_status st)
{
    fg_buf b;
    if (st != FG_OK) { send_err(s, "500 Internal Server Error", fg_strerror(st)); return; }
    fg_buf_init(&b);
    fg_buf_printf(&b, "{\"job\":\"%s\"}", fg_job_id(j));
    send_json(s, "202 Accepted", b.data);
    fg_buf_free(&b);
}

static void api_erase_drive(fg_socket s, const req *r)
{
    fg_jval *o = fg_json_parse(r->body ? r->body : "{}");
    const char *dev = fg_json_gets(o, "device", NULL);
    fg_drive_opts d;
    fg_job *j;
    char title[256];

    if (!dev) { fg_json_free(o); send_err(s, "400 Bad Request", "device is required"); return; }
    fg_drive_opts_default(&d);
    d.method            = method_from(o, "method", FG_M_NIST_CLEAR);
    d.verify            = verify_from(o);
    d.allow_system_disk = fg_json_getb(o, "allow_system_disk", 0);
    d.dry_run           = fg_json_getb(o, "dry_run", 0);
    d.use_firmware      = fg_json_getb(o, "use_firmware", 1);
    d.trim_after        = fg_json_getb(o, "trim_after", 1);
    d.confirm_token     = fg_json_gets(o, "confirm", NULL);
    d.case_id           = fg_json_gets(o, "case_id", "");
    d.operator_name     = fg_json_gets(o, "operator", "");

    snprintf(title, sizeof title, "Erase %s (%s)", dev, fg_method_get(d.method)->name);
    j = fg_job_create(FG_JOB_DRIVE_ERASE, title);
    if (!j) { fg_json_free(o); send_err(s, "503 Service Unavailable", "job table full"); return; }
    reply_job(s, j, fg_job_start_drive(j, dev, &d));
    fg_json_free(o);
}

static void api_erase_files(fg_socket s, const req *r)
{
    fg_jval *o = fg_json_parse(r->body ? r->body : "{}");
    fg_jval *arr = fg_json_get(o, "paths");
    fg_file_opts f;
    fg_job *j;
    const char *plist[256];
    int n = 0;

    if (arr && arr->type == FG_JS_ARR) {
        fg_jval *c;
        for (c = arr->child; c && n < 256; c = c->next)
            if (c->type == FG_JS_STR && c->child && c->child->str) plist[n++] = c->child->str;
    }
    if (!n) { fg_json_free(o); send_err(s, "400 Bad Request", "paths[] is required"); return; }

    fg_file_opts_default(&f);
    f.method          = method_from(o, "method", FG_M_DOD_3);
    f.verify          = verify_from(o);
    f.recursive       = fg_json_getb(o, "recursive", 1);
    f.remove_metadata = fg_json_getb(o, "remove_metadata", 1);
    f.wipe_slack      = fg_json_getb(o, "wipe_slack", 1);
    f.remove_empty_dirs = fg_json_getb(o, "remove_empty_dirs", 0);
    f.dry_run         = fg_json_getb(o, "dry_run", 0);
    f.include_glob    = fg_json_gets(o, "include", NULL);
    f.exclude_glob    = fg_json_gets(o, "exclude", NULL);
    f.case_id         = fg_json_gets(o, "case_id", "");
    f.operator_name   = fg_json_gets(o, "operator", "");

    j = fg_job_create(FG_JOB_FILE_ERASE, "Secure file erasure");
    if (!j) { fg_json_free(o); send_err(s, "503 Service Unavailable", "job table full"); return; }
    reply_job(s, j, fg_job_start_files(j, plist, n, &f));
    fg_json_free(o);
}

static void api_freespace(fg_socket s, const req *r)
{
    fg_jval *o = fg_json_parse(r->body ? r->body : "{}");
    const char *vol = fg_json_gets(o, "volume", NULL);
    fg_job *j;
    char title[256];
    if (!vol) { fg_json_free(o); send_err(s, "400 Bad Request", "volume is required"); return; }
    snprintf(title, sizeof title, "Wipe free space on %s", vol);
    j = fg_job_create(FG_JOB_FREESPACE, title);
    if (!j) { fg_json_free(o); send_err(s, "503 Service Unavailable", "job table full"); return; }
    reply_job(s, j, fg_job_start_freespace(j, vol, method_from(o, "method", FG_M_RANDOM)));
    fg_json_free(o);
}

static void api_recover(fg_socket s, const req *r)
{
    fg_jval *o = fg_json_parse(r->body ? r->body : "{}");
    const char *src = fg_json_gets(o, "source", NULL);
    fg_scan_opts sc;
    fg_job *j;
    char title[256];

    if (!src) { fg_json_free(o); send_err(s, "400 Bad Request", "source is required"); return; }
    fg_scan_opts_default(&sc);
    sc.out_dir          = fg_json_gets(o, "out_dir", NULL);
    sc.types            = fg_json_gets(o, "types", NULL);
    sc.categories       = fg_json_gets(o, "categories", NULL);
    sc.do_metadata      = fg_json_getb(o, "metadata", 1);
    sc.do_carve         = fg_json_getb(o, "carve", 1);
    sc.do_fragment      = fg_json_getb(o, "fragment", 1);
    sc.unallocated_only = fg_json_getb(o, "unallocated_only", 0);
    sc.write_files      = fg_json_getb(o, "write_files", 1);
    sc.min_confidence   = (int)fg_json_getn(o, "min_confidence", 30);
    sc.max_results      = (int)fg_json_getn(o, "max_results", 0);
    sc.start_offset     = (uint64_t)fg_json_getn(o, "start_offset", 0);
    sc.end_offset       = (uint64_t)fg_json_getn(o, "end_offset", 0);
    sc.case_id          = fg_json_gets(o, "case_id", "");
    sc.operator_name    = fg_json_gets(o, "operator", "");

    snprintf(title, sizeof title, "Recover from %s", src);
    j = fg_job_create(FG_JOB_SCAN, title);
    if (!j) { fg_json_free(o); send_err(s, "503 Service Unavailable", "job table full"); return; }
    reply_job(s, j, fg_job_start_scan(j, src, &sc));
    fg_json_free(o);
}

static void api_report(fg_socket s, const req *r, const char *id)
{
    char fmtstr[16];
    fg_report_fmt fmt = FG_RPT_HTML;
    fg_report_meta m;
    fg_buf out;
    fg_job *j = fg_job_find(id);

    if (!j) { send_err(s, "404 Not Found", "no such job"); return; }
    if (query_get(r->query, "format", fmtstr, sizeof fmtstr)) {
        if (!strcmp(fmtstr, "json")) fmt = FG_RPT_JSON;
        else if (!strcmp(fmtstr, "csv")) fmt = FG_RPT_CSV;
        else if (!strcmp(fmtstr, "text")) fmt = FG_RPT_TEXT;
    }
    memset(&m, 0, sizeof m);
    m.session_id      = g_audit_ref ? fg_audit_session_id(g_audit_ref) : "";
    m.audit_head_hash = g_audit_ref ? fg_audit_head_hash(g_audit_ref) : "";
    if (fg_job_report(j, fmt, &m, &out) != FG_OK) {
        send_err(s, "409 Conflict", "the job has not produced a report yet");
        return;
    }
    send_raw(s, "200 OK",
             fmt == FG_RPT_JSON ? "application/json; charset=utf-8" :
             fmt == FG_RPT_CSV  ? "text/csv; charset=utf-8" :
             fmt == FG_RPT_TEXT ? "text/plain; charset=utf-8" :
                                  "text/html; charset=utf-8",
             out.data ? out.data : "", out.len);
    fg_buf_free(&out);
}

static void api_audit_verify(fg_socket s, const req *r)
{
    fg_jval *o = fg_json_parse(r->body ? r->body : "{}");
    const char *path = fg_json_gets(o, "path", NULL);
    const char *keyhex = fg_json_gets(o, "key", NULL);
    fg_audit_verify v;
    uint8_t key[32];
    int klen = 0;
    fg_jw w;

    if (!path) { fg_json_free(o); send_err(s, "400 Bad Request", "path is required"); return; }
    if (keyhex && *keyhex) klen = fg_hex_decode(keyhex, key, sizeof key);
    fg_audit_verify_file(path, klen > 0 ? key : NULL, klen > 0 ? (size_t)klen : 0, &v);

    fg_jw_init(&w, 0);
    fg_jw_obj(&w);
    fg_jw_kbool(&w, "chain_ok", v.chain_ok);
    fg_jw_kbool(&w, "seal_checked", v.seal_checked);
    fg_jw_kbool(&w, "seal_ok", v.seal_ok);
    fg_jw_ku64(&w, "records", v.records);
    fg_jw_ku64(&w, "first_bad_record", v.first_bad_record);
    fg_jw_kstr(&w, "head_hash", v.head_hash);
    fg_jw_kstr(&w, "session", v.session_id);
    fg_jw_kstr(&w, "operator", v.operator_name);
    fg_jw_kstr(&w, "case", v.case_id);
    fg_jw_kstr(&w, "message", v.message);
    fg_jw_obj_end(&w);
    send_json(s, "200 OK", fg_jw_text(&w));
    fg_jw_free(&w);
    fg_json_free(o);
}

/* ---- request handling ---------------------------------------------------- */
static void handle(fg_socket c)
{
    char *buf = (char *)malloc(REQ_MAX);
    int total = 0, n;
    char *hdr_end = NULL;
    req r;
    size_t content_len = 0;

    if (!buf) { fg_net_close(c); return; }
    memset(&r, 0, sizeof r);

    /* read headers */
    while (total < REQ_MAX - 1) {
        n = fg_net_recv(c, buf + total, REQ_MAX - 1 - total);
        if (n <= 0) break;
        total += n;
        buf[total] = '\0';
        hdr_end = strstr(buf, "\r\n\r\n");
        if (hdr_end) break;
    }
    if (!hdr_end) { free(buf); fg_net_close(c); return; }

    /* request line */
    {
        char *sp1 = strchr(buf, ' ');
        char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
        char *q;
        if (!sp1 || !sp2) { free(buf); fg_net_close(c); return; }
        *sp1 = '\0';
        snprintf(r.method, sizeof r.method, "%s", buf);
        *sp2 = '\0';
        snprintf(r.path, sizeof r.path, "%s", sp1 + 1);
        *sp1 = ' '; *sp2 = ' ';
        q = strchr(r.path, '?');
        if (q) { *q = '\0'; snprintf(r.query, sizeof r.query, "%s", q + 1); }
        url_decode(r.path);
    }
    /* headers we care about */
    {
        const char *p = strstr(buf, "Content-Length:");
        if (p && (!hdr_end || p < hdr_end)) content_len = (size_t)strtoul(p + 15, NULL, 10);
        p = strstr(buf, "X-Forge-Token:");
        if (p && (!hdr_end || p < hdr_end)) {
            const char *e;
            p += 15;
            while (*p == ' ') p++;
            e = strstr(p, "\r\n");
            if (e && (size_t)(e - p) < sizeof r.token) {
                memcpy(r.token, p, (size_t)(e - p));
                r.token[e - p] = '\0';
            }
        }
    }
    if (!r.token[0]) query_get(r.query, "token", r.token, sizeof r.token);

    /* body */
    {
        size_t have = (size_t)(total - (int)(hdr_end + 4 - buf));
        if (content_len > (size_t)REQ_MAX - 1) content_len = REQ_MAX - 1;
        while (have < content_len && total < REQ_MAX - 1) {
            n = fg_net_recv(c, buf + total, (int)FG_MIN((size_t)(REQ_MAX - 1 - total),
                                                        content_len - have));
            if (n <= 0) break;
            total += n;
            have += (size_t)n;
        }
        buf[total] = '\0';
        r.body = hdr_end + 4;
        r.body_len = have;
        r.body[FG_MIN(have, (size_t)(REQ_MAX - 1))] = '\0';
    }

    /* ---- routing ---- */
    if (!strcmp(r.path, "/") || !strcmp(r.path, "/index.html")) {
        /* The page carries the session token so the browser can call the API
         * without the operator pasting it anywhere. */
        fg_buf page;
        const char *marker = "__FORGE_TOKEN__";
        const char *src = (const char *)fg_ui_dashboard_html;
        const char *hit = strstr(src, marker);
        fg_buf_init(&page);
        if (hit) {
            fg_buf_append(&page, src, (size_t)(hit - src));
            fg_buf_puts(&page, g_token);
            fg_buf_puts(&page, hit + strlen(marker));
        } else {
            fg_buf_append(&page, src, fg_ui_dashboard_html_len);
        }
        send_raw(c, "200 OK", "text/html; charset=utf-8", page.data, page.len);
        fg_buf_free(&page);
        free(buf);
        fg_net_close(c);
        return;
    }

    if (strncmp(r.path, "/api/", 5)) {
        send_err(c, "404 Not Found", "no such resource");
        free(buf);
        fg_net_close(c);
        return;
    }
    if (strcmp(r.token, g_token)) {
        send_err(c, "401 Unauthorized",
                 "missing or invalid X-Forge-Token; the token is printed when the "
                 "server starts");
        free(buf);
        fg_net_close(c);
        return;
    }

    if (!strcmp(r.path, "/api/system"))          api_system(c);
    else if (!strcmp(r.path, "/api/devices"))    api_devices(c);
    else if (!strcmp(r.path, "/api/methods"))    api_methods(c);
    else if (!strcmp(r.path, "/api/signatures")) api_signatures(c);
    else if (!strcmp(r.path, "/api/jobs")) {
        fg_buf b;
        fg_buf_init(&b);
        fg_jobs_to_json(NULL, &b);
        send_json(c, "200 OK", b.data ? b.data : "[]");
        fg_buf_free(&b);
    }
    else if (!strncmp(r.path, "/api/jobs/", 10)) {
        char id[64];
        const char *rest;
        size_t idlen;
        rest = strchr(r.path + 10, '/');
        idlen = rest ? (size_t)(rest - (r.path + 10)) : strlen(r.path + 10);
        if (idlen >= sizeof id) idlen = sizeof id - 1;
        memcpy(id, r.path + 10, idlen);
        id[idlen] = '\0';
        if (rest && !strcmp(rest, "/cancel")) {
            fg_job_cancel(id);
            send_json(c, "200 OK", "{\"cancelled\":true}");
        } else if (rest && !strcmp(rest, "/report")) {
            api_report(c, &r, id);
        } else {
            fg_buf b;
            fg_buf_init(&b);
            fg_jobs_to_json(id, &b);
            send_json(c, "200 OK", b.data ? b.data : "{}");
            fg_buf_free(&b);
        }
    }
    else if (!strcmp(r.path, "/api/erase/drive") && !strcmp(r.method, "POST"))
        api_erase_drive(c, &r);
    else if (!strcmp(r.path, "/api/erase/files") && !strcmp(r.method, "POST"))
        api_erase_files(c, &r);
    else if (!strcmp(r.path, "/api/erase/freespace") && !strcmp(r.method, "POST"))
        api_freespace(c, &r);
    else if (!strcmp(r.path, "/api/recover") && !strcmp(r.method, "POST"))
        api_recover(c, &r);
    else if (!strcmp(r.path, "/api/audit/verify") && !strcmp(r.method, "POST"))
        api_audit_verify(c, &r);
    else
        send_err(c, "404 Not Found", "no such endpoint");

    free(buf);
    fg_net_close(c);
}

typedef struct { fg_socket c; } conn_arg;

static void conn_thread(void *p)
{
    conn_arg *a = (conn_arg *)p;
    fg_socket c = a->c;
    free(a);
    fg_net_set_timeout(c, 30);
    handle(c);
}

fg_status fg_server_run(const fg_server_opts *o)
{
    fg_socket srv;
    const char *bind_addr = (o && o->bind_addr) ? o->bind_addr : "127.0.0.1";
    int port = (o && o->port) ? o->port : 8787;

    g_stop = 0;
    g_audit_ref = o ? o->audit : NULL;
    if (o && o->token && *o->token) snprintf(g_token, sizeof g_token, "%s", o->token);
    else fg_make_id(g_token);

    if (fg_net_startup() != FG_OK) return FG_ERR_GENERIC;
    srv = fg_net_listen(bind_addr, port);
    if (srv == FG_INVALID_SOCKET) {
        fg_net_cleanup();
        return FG_ERR_BUSY;
    }

    printf("\n  %s %s - %s\n", FG_PRODUCT, FG_VERSION_STR, FG_TAGLINE);
    printf("  Dashboard : http://%s:%d/?token=%s\n", bind_addr, port, g_token);
    printf("  API token : %s\n", g_token);
    printf("  Privileges: %s\n", fg_is_elevated() ? "elevated" :
           "NOT elevated - raw device operations will be refused");
    printf("  Press Ctrl-C to stop.\n\n");
    fflush(stdout);

    while (!g_stop) {
        char peer[64];
        fg_socket c = fg_net_accept(srv, peer, sizeof peer);
        conn_arg *a;
        fg_thread *t = NULL;
        if (c == FG_INVALID_SOCKET) {
            if (g_stop) break;
            fg_sleep_ms(20);
            continue;
        }
        /* Loopback-only by default; anything else is an explicit choice. */
        a = (conn_arg *)fg_xcalloc(1, sizeof *a);
        if (!a) { fg_net_close(c); continue; }
        a->c = c;
        if (fg_thread_start(&t, conn_thread, a) != FG_OK) {
            conn_thread(a);
        } else {
            fg_thread_detach(t);
        }
    }

    fg_net_close(srv);
    fg_net_cleanup();
    return FG_OK;
}
