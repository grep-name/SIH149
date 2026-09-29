#include "forge/fg_erase.h"
#include "forge/fg_carve.h"
#include "forge/fg_fs.h"

#include "forge/fg_audit.h"
#include "forge/fg_ui.h"
#include "forge/fg_json.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


static int   g_json = 0;
static int   g_quiet = 0;
static char  g_audit_path[4096] = "forge-audit.log";

static fg_audit *g_audit = NULL;

static void banner(void)
{
    if (g_quiet || g_json) return;
    printf("%s %s - %s\n", FG_PRODUCT, FG_VERSION_STR, FG_TAGLINE);
}

static void usage(void)
{
    printf(
"%s %s - %s\n"
"\n"
"USAGE\n"
"  forge <command> [subcommand] [options]\n"
"\n"
"DISCOVERY\n"
"  devices                       list attached storage devices\n"
"  methods                       list sanitization standards\n"
"  types                         list recoverable file signatures\n"
"  parts --source <dev|image>    show the partition table and filesystems\n"
"\n"
"MODULE 1 - SECURE DRIVE ERASER\n"
"  erase drive --device <path> --confirm <serial|ERASE> [options]\n"
"      --method <id>        sanitization standard (default nist-clear)\n"
"      --verify <mode>      none | sample | full        (default sample)\n"
"      --no-firmware        skip ATA/NVMe sanitize, overwrite only\n"
"      --no-trim            do not issue TRIM after the passes\n"
"      --allow-system-disk  permit a mounted or OS-bearing disk (dangerous)\n"
"      --dry-run            report what would happen and stop\n"
"      --report <file>      write a certificate (.html .json .csv .txt)\n"
"\n"
"MODULE 2 - SECURE FILE AND FOLDER ERASER\n"
"  erase file <path> [path...] [options]\n"
"      --method <id>        default dod3\n"
"      --verify <mode>      default sample\n"
"      --no-recurse         do not descend into subfolders\n"
"      --no-metadata        keep names, timestamps, ADS and xattrs\n"
"      --no-slack           do not wipe cluster slack\n"
"      --rmdir              remove directories left empty\n"
"      --include <globs>    comma separated, e.g. *.docx,*.pdf\n"
"      --exclude <globs>\n"
"      --dry-run            list targets without touching them\n"
"      --report <file>\n"
"  erase freespace --volume <path> [--method <id>]\n"
"\n"
"MODULE 3 - ADVANCED FILE CARVING AND RECOVERY\n"
"  recover --source <dev|image> [options]\n"
"      --out <dir>          where to write recovered files\n"
"      --types <list>       jpg,pdf,docx,...  (default: every type)\n"
"      --categories <list>  image,document,archive,...\n"
"      --min-confidence <n> discard results below n (default 30)\n"
"      --no-metadata        skip filesystem parsing, carve only\n"
"      --no-carve           filesystem metadata recovery only\n"
"      --no-fragment        disable bi-fragment gap carving\n"
"      --unallocated-only   ignore clusters that are currently allocated\n"
"      --catalogue-only     do not extract, just list what is there\n"
"      --start <bytes> --end <bytes>\n"
"      --max <n>            stop after n files\n"
"      --report <file>\n"
"\n"
"AUDIT AND REPORTING\n"
"  audit verify --log <file> [--key <hex>]\n"
"  --audit-log <file>       where this session appends (default forge-audit.log)\n"
"  --case <id> --operator <name> --org <name>\n"
"\n"
"USER INTERFACE\n"
"  serve [--port 8787] [--bind 127.0.0.1] [--token <hex>]\n"
"\n"
"GLOBAL\n"
"  --json                   machine-readable output\n"
"  --quiet   --verbose   --version   --help\n"
"\n"
"Raw device operations require Administrator (Windows) or root (Linux/macOS).\n",
    FG_PRODUCT, FG_VERSION_STR, FG_TAGLINE);
}


static const char *opt(int argc, char **argv, const char *name, const char *fb)
{
    int i;
    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], name) && i + 1 < argc) return argv[i + 1];

    return fb;
}

static int flag(int argc, char **argv, const char *name)
{
    int i;
    for (i = 1; i < argc; i++) if (!strcmp(argv[i], name)) return 1;
    return 0;
}

static fg_verify_mode parse_verify(const char *s)
{
    if (!s) return FG_VERIFY_SAMPLE;
    if (!strcmp(s, "none")) return FG_VERIFY_NONE;

    if (!strcmp(s, "full")) return FG_VERIFY_FULL;
    return FG_VERIFY_SAMPLE;
}

static fg_report_fmt fmt_from_path(const char *p)
{
    if (!p) return FG_RPT_TEXT;
    if (fg_str_endswith(p, ".json")) return FG_RPT_JSON;
    if (fg_str_endswith(p, ".csv"))  return FG_RPT_CSV;
    if (fg_str_endswith(p, ".txt"))  return FG_RPT_TEXT;
    return FG_RPT_HTML;
}

static void fill_meta(fg_report_meta *m, int argc, char **argv)
{
    memset(m, 0, sizeof *m);

    m->case_id       = opt(argc, argv, "--case", "");
    m->operator_name = opt(argc, argv, "--operator", "");
    m->organisation  = opt(argc, argv, "--org", "");
    m->notes         = opt(argc, argv, "--notes", "");
    m->audit_log_path = g_audit_path;
    m->session_id    = g_audit ? fg_audit_session_id(g_audit) : "";
    m->audit_head_hash = g_audit ? fg_audit_head_hash(g_audit) : "";
}


static uint64_t g_last_tick = 0;


static int cli_progress(void *user, const char *phase, uint64_t done,
                        uint64_t total, const char *detail)
{
    uint64_t now;
    int i, filled;
    double pct;
    FG_UNUSED(user);
    if (g_quiet || g_json) return 0;
    now = fg_now_ms();
    if (now - g_last_tick < 120 && done < total) return 0;
    g_last_tick = now;
    pct = total ? (double)done * 100.0 / (double)total : 0.0;
    filled = (int)(pct / 2.5);
    fprintf(stderr, "\r  %-12s [", phase ? phase : "");
    for (i = 0; i < 40; i++) fputc(i < filled ? '#' : '.', stderr);
    fprintf(stderr, "] %6.2f%%", pct);
    if (detail && *detail) {
        size_t n = strlen(detail);
        fprintf(stderr, "  %s", n > 40 ? detail + n - 40 : detail);
    }
    fprintf(stderr, "   ");
    fflush(stderr);
    return 0;
}

static void progress_done(void)
{
    if (!g_quiet && !g_json) fprintf(stderr, "\n");
}


static int cmd_devices(void)
{
    fg_device_info list[64];
    int n = fg_dev_enumerate(list, 64), i;

    if (n < 0) { fprintf(stderr, "error: %s\n", fg_strerror((fg_status)n)); return 1; }
    if (g_json) {
        fg_jw w;
        fg_jw_init(&w, 1);
        fg_jw_arr(&w);
        for (i = 0; i < n; i++) {

            fg_jw_obj(&w);
            fg_jw_kstr(&w, "id", list[i].id);
            fg_jw_kstr(&w, "model", list[i].model);
            fg_jw_kstr(&w, "serial", list[i].serial);
            fg_jw_ku64(&w, "size_bytes", list[i].size_bytes);
            fg_jw_ku64(&w, "sector_size", list[i].logical_sector);
            fg_jw_kbool(&w, "removable", list[i].removable);
            fg_jw_kbool(&w, "system_disk", list[i].is_system);
            fg_jw_kbool(&w, "mounted", list[i].has_mounted_fs);
            fg_jw_kstr(&w, "mountpoints", list[i].mountpoints);
            fg_jw_obj_end(&w);
        }
        fg_jw_arr_end(&w);
        printf("%s\n", fg_jw_text(&w));
        fg_jw_free(&w);
        return 0;
    }
    if (!n) {
        printf("No storage devices visible.%s\n",
               fg_is_elevated() ? "" : " Run elevated to enumerate raw devices.");
        return 0;
    }
    printf("\n%-24s %-26s %-18s %10s  %-14s %s\n",
           "DEVICE", "MODEL", "SERIAL", "CAPACITY", "TYPE", "MOUNTED");
    printf("%.*s\n", 118,
           "--------------------------------------------------------------"
           "--------------------------------------------------------------");
    for (i = 0; i < n; i++) {
        char cap[32], type[32];
        fg_human_size(list[i].size_bytes, cap, sizeof cap);
        snprintf(type, sizeof type, "%s/%s",
                 list[i].media == FG_MEDIA_SSD ? "SSD" :
                 list[i].media == FG_MEDIA_HDD ? "HDD" :
                 list[i].media == FG_MEDIA_FLASH ? "Flash" :
                 list[i].media == FG_MEDIA_OPTICAL ? "Optical" : "?",
                 list[i].bus == FG_BUS_NVME ? "NVMe" :
                 list[i].bus == FG_BUS_SATA ? "SATA" :
                 list[i].bus == FG_BUS_ATA  ? "ATA"  :
                 list[i].bus == FG_BUS_USB  ? "USB"  :
                 list[i].bus == FG_BUS_SCSI ? "SCSI" :
                 list[i].bus == FG_BUS_SD   ? "SD"   :
                 list[i].bus == FG_BUS_MMC  ? "MMC"  : "?");
        printf("%-24s %-26.26s %-18.18s %10s  %-14s %s%s\n",
               list[i].id, list[i].model,
               list[i].serial[0] ? list[i].serial : "-", cap, type,
               list[i].mountpoints[0] ? list[i].mountpoints : "-",
               list[i].is_system ? "  [SYSTEM DISK]" : "");
    }
    printf("\n");
    return 0;
}

static void print_method(void *user, const fg_method_def *d)
{
    FG_UNUSED(user);
    printf("  %-12s %-26s %2d pass%-3s %s\n",
           d->cli_name, d->name, d->pass_count, d->pass_count == 1 ? "" : "es",
           d->standard);
}

static int cmd_methods(void)
{
    printf("\nSanitization methods (--method <id>):\n\n");
    fg_method_list(print_method, NULL);
    printf("\n  Methods marked NIST 800-88 Purge attempt an ATA/NVMe firmware\n"
           "  sanitize first and fall back to overwriting if the device refuses.\n\n");
    return 0;
}

static int cmd_types(void)
{
    int n, i;
    const fg_sig *t = fg_sig_table(&n);
    printf("\n%d recoverable file signatures:\n\n", n);
    printf("  %-8s %-10s %-6s %s\n", "EXT", "CATEGORY", "STRUCT", "DESCRIPTION");
    for (i = 0; i < n; i++)
        printf("  %-8s %-10s %-6s %s\n", t[i].ext,
               fg_category_name(t[i].category),
               t[i].validate ? "yes" : (t[i].footer ? "footer" : "-"), t[i].desc);
    printf("\n  STRUCT=yes means the exact file length is read from the format's own\n"
           "  headers rather than guessed, which is what makes a carve reliable.\n\n");
    return 0;
}

static int cmd_parts(int argc, char **argv)
{
    const char *src = opt(argc, argv, "--source", NULL);
    fg_dev *d = NULL;
    fg_partition_table pt;
    int i;
    if (!src) { fprintf(stderr, "error: --source is required\n"); return 2; }
    if (fg_dev_open(src, FG_DEV_READ, &d) != FG_OK) {
        fprintf(stderr, "error: cannot open %s\n", src);
        return 1;
    }
    if (fg_parts_read(d, &pt) != FG_OK || !pt.count) {
        uint8_t boot[4096];
        size_t got = 0;
        char label[72] = "";
        printf("No partition table found.\n");
        if (fg_dev_pread(d, boot, sizeof boot, 0, &got) == FG_OK && got >= 512) {
            fg_fs_kind k = fg_fs_identify(boot, got, label, sizeof label);
            printf("Whole-device filesystem: %s %s\n", fg_fs_kind_name(k), label);
        }
        fg_dev_close(d);
        return 0;
    }
    printf("\n%s partition table, sector size %u\n\n",
           pt.scheme == 2 ? "GPT" : "MBR", pt.sector_size);
    printf("  %-3s %14s %14s %12s  %-8s %s\n",
           "#", "START(LBA)", "SECTORS", "SIZE", "FS", "LABEL/TYPE");
    for (i = 0; i < pt.count; i++) {
        char sz[32];
        fg_human_size(pt.parts[i].size_bytes, sz, sizeof sz);
        printf("  %-3d %14llu %14llu %12s  %-8s %s\n", pt.parts[i].index,
               (unsigned long long)pt.parts[i].start_lba,
               (unsigned long long)pt.parts[i].sector_count, sz,
               fg_fs_kind_name(pt.parts[i].fs), pt.parts[i].label);
    }
    printf("\n");
    fg_dev_close(d);
    return 0;
}


static int cmd_erase_drive(int argc, char **argv)
{
    fg_drive_opts o;
    fg_drive_result res;
    fg_report_meta meta;
    const char *dev = opt(argc, argv, "--device", NULL);
    const char *mname = opt(argc, argv, "--method", "nist-clear");
    const char *report = opt(argc, argv, "--report", NULL);
    fg_method m;
    fg_status st;

    if (!dev) { fprintf(stderr, "error: --device is required\n"); return 2; }
    m = fg_method_parse(mname);
    if (m == (fg_method)-1) {
        fprintf(stderr, "error: unknown method '%s' (try: forge methods)\n", mname);
        return 2;
    }

    fg_drive_opts_default(&o);
    o.method            = m;
    o.verify            = parse_verify(opt(argc, argv, "--verify", "sample"));
    o.use_firmware      = !flag(argc, argv, "--no-firmware");
    o.trim_after        = !flag(argc, argv, "--no-trim");
    o.allow_system_disk = flag(argc, argv, "--allow-system-disk");
    o.dry_run           = flag(argc, argv, "--dry-run");
    o.confirm_token     = opt(argc, argv, "--confirm", NULL);
    o.case_id           = opt(argc, argv, "--case", "");
    o.operator_name     = opt(argc, argv, "--operator", "");
    o.progress.fn       = cli_progress;

    if (!g_quiet && !g_json) {
        const fg_method_def *def = fg_method_get(m);
        printf("\n  Target  : %s\n  Method  : %s (%d pass%s)\n  Standard: %s\n  Verify  : %s\n\n",
               dev, def->name, def->pass_count, def->pass_count == 1 ? "" : "es",
               def->standard,
               o.verify == FG_VERIFY_FULL ? "full read-back" :
               o.verify == FG_VERIFY_SAMPLE ? "statistical sample" : "none");
    }

    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_ERASE_BEGIN, FG_OK, dev,
                        "\"method\":\"%s\",\"dry_run\":%s",
                        fg_method_get(m)->cli_name, o.dry_run ? "true" : "false");

    st = fg_drive_erase(dev, &o, &res);
    progress_done();

    if (g_audit)
        fg_audit_eventf(g_audit, st == FG_OK ? FG_EV_ERASE_END : FG_EV_REFUSED, st, dev,
                        "\"report\":\"%s\",\"bytes\":%llu,\"verified\":%s,\"message\":\"%s\"",
                        res.report_id, (unsigned long long)res.bytes_written,
                        res.verify.passed ? "true" : "false", res.message);

    fill_meta(&meta, argc, argv);
    if (g_json) {
        fg_buf b;
        fg_report_drive_buf(&res, &meta, FG_RPT_JSON, &b);
        fwrite(b.data, 1, b.len, stdout);
        fg_buf_free(&b);
    } else {
        fg_buf b;
        fg_report_drive_buf(&res, &meta, FG_RPT_TEXT, &b);
        printf("\n%s\n", b.data ? b.data : "");
        fg_buf_free(&b);
    }
    if (report) {
        if (fg_report_drive(&res, &meta, fmt_from_path(report), report) == FG_OK) {
            if (!g_json) printf("Certificate written to %s\n", report);
        } else {
            fprintf(stderr, "warning: could not write %s\n", report);
        }
    }
    return st == FG_OK ? 0 : 1;
}

static int cmd_erase_file(int argc, char **argv)
{
    fg_file_opts o;
    fg_file_result res;
    fg_report_meta meta;
    const char *paths[512];
    int npaths = 0, i;
    const char *mname = opt(argc, argv, "--method", "dod3");
    const char *report = opt(argc, argv, "--report", NULL);
    fg_method m = fg_method_parse(mname);
    fg_status st;

    if (m == (fg_method)-1) {
        fprintf(stderr, "error: unknown method '%s'\n", mname);
        return 2;
    }

    for (i = 3; i < argc && npaths < 512; i++) {
        if (argv[i][0] == '-') {

            static const char *valued[] = {"--method","--verify","--include","--exclude",
                                           "--report","--case","--operator","--org",
                                           "--notes","--audit-log","--max-size"};
            size_t k;
            for (k = 0; k < FG_ARRAY_LEN(valued); k++)
                if (!strcmp(argv[i], valued[k])) { i++; break; }
            continue;
        }
        paths[npaths++] = argv[i];
    }
    if (!npaths) { fprintf(stderr, "error: no paths given\n"); return 2; }

    fg_file_opts_default(&o);
    o.method          = m;
    o.verify          = parse_verify(opt(argc, argv, "--verify", "sample"));
    o.recursive       = !flag(argc, argv, "--no-recurse");
    o.remove_metadata = !flag(argc, argv, "--no-metadata");
    o.wipe_slack      = !flag(argc, argv, "--no-slack");
    o.remove_empty_dirs = flag(argc, argv, "--rmdir");
    o.dry_run         = flag(argc, argv, "--dry-run");
    o.include_glob    = opt(argc, argv, "--include", NULL);
    o.exclude_glob    = opt(argc, argv, "--exclude", NULL);
    o.case_id         = opt(argc, argv, "--case", "");
    o.operator_name   = opt(argc, argv, "--operator", "");
    o.progress.fn     = cli_progress;

    st = fg_file_erase_paths(paths, npaths, &o, &res);
    progress_done();

    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_FILE_ERASE, st, paths[0],
                        "\"paths\":%d,\"erased\":%llu,\"failed\":%llu,\"bytes\":%llu,"
                        "\"method\":\"%s\",\"report\":\"%s\"",
                        npaths, (unsigned long long)res.files_erased,
                        (unsigned long long)res.files_failed,
                        (unsigned long long)res.bytes_erased,
                        fg_method_get(m)->cli_name, res.report_id);

    fill_meta(&meta, argc, argv);
    {
        fg_buf b;
        fg_report_files_buf(&res, &meta, g_json ? FG_RPT_JSON : FG_RPT_TEXT, &b);
        if (g_json) fwrite(b.data, 1, b.len, stdout);
        else        printf("\n%s\n", b.data ? b.data : "");
        fg_buf_free(&b);
    }
    if (report && fg_report_files(&res, &meta, fmt_from_path(report), report) == FG_OK && !g_json)
        printf("Report written to %s\n", report);

    fg_file_result_free(&res);
    return (st == FG_OK) ? 0 : 1;
}

static int cmd_erase_freespace(int argc, char **argv)
{
    const char *vol = opt(argc, argv, "--volume", NULL);
    fg_method m = fg_method_parse(opt(argc, argv, "--method", "random"));
    fg_freespace_result res;
    fg_progress pg;
    fg_status st;
    char sz[32];

    if (!vol) { fprintf(stderr, "error: --volume is required\n"); return 2; }
    if (m == (fg_method)-1) m = FG_M_RANDOM;
    pg.fn = cli_progress;
    pg.user = NULL;
    st = fg_wipe_free_space(vol, m, 1, &pg, &res);
    progress_done();
    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_FREESPACE, st, vol,
                        "\"bytes\":%llu,\"records\":%llu",
                        (unsigned long long)res.bytes_written,
                        (unsigned long long)res.mft_records_wiped);
    fg_human_size(res.bytes_written, sz, sizeof sz);
    if (g_json)
        printf("{\"bytes_written\":%llu,\"directory_records_wiped\":%llu,"
               "\"free_before_gb\":%.2f,\"free_after_gb\":%.2f,\"seconds\":%.2f,"
               "\"status\":%d}\n",
               (unsigned long long)res.bytes_written,
               (unsigned long long)res.mft_records_wiped,
               res.free_before_gb, res.free_after_gb, res.seconds, (int)st);
    else
        printf("\nFree-space wipe on %s\n  overwritten     : %s\n"
               "  directory slots : %llu\n  free before/after: %.2f / %.2f GB\n"
               "  elapsed         : %.1f s\n  result          : %s\n\n",
               vol, sz, (unsigned long long)res.mft_records_wiped,
               res.free_before_gb, res.free_after_gb, res.seconds, fg_strerror(st));
    return st == FG_OK ? 0 : 1;
}


static int cmd_recover(int argc, char **argv)
{
    fg_scan_opts o;
    fg_scan_result res;
    fg_report_meta meta;
    const char *src = opt(argc, argv, "--source", NULL);
    const char *report = opt(argc, argv, "--report", NULL);
    fg_status st;

    if (!src) { fprintf(stderr, "error: --source is required\n"); return 2; }

    fg_scan_opts_default(&o);
    o.out_dir          = opt(argc, argv, "--out", "recovered");
    o.types            = opt(argc, argv, "--types", NULL);
    o.categories       = opt(argc, argv, "--categories", NULL);
    o.min_confidence   = atoi(opt(argc, argv, "--min-confidence", "30"));
    o.do_metadata      = !flag(argc, argv, "--no-metadata");
    o.do_carve         = !flag(argc, argv, "--no-carve");
    o.do_fragment      = !flag(argc, argv, "--no-fragment");
    o.unallocated_only = flag(argc, argv, "--unallocated-only");
    o.write_files      = !flag(argc, argv, "--catalogue-only");
    o.start_offset     = strtoull(opt(argc, argv, "--start", "0"), NULL, 0);
    o.end_offset       = strtoull(opt(argc, argv, "--end", "0"), NULL, 0);
    o.max_results      = atoi(opt(argc, argv, "--max", "0"));
    o.case_id          = opt(argc, argv, "--case", "");
    o.operator_name    = opt(argc, argv, "--operator", "");
    o.progress.fn      = cli_progress;

    if (!g_quiet && !g_json)
        printf("\n  Source  : %s\n  Output  : %s\n  Strategy: %s%s%s\n\n", src,
               o.write_files ? o.out_dir : "(catalogue only)",
               o.do_metadata ? "filesystem metadata" : "",
               (o.do_metadata && o.do_carve) ? " + " : "",
               o.do_carve ? (o.do_fragment ? "structure carving + gap carving"
                                           : "structure carving") : "");

    if (g_audit) fg_audit_eventf(g_audit, FG_EV_SCAN_BEGIN, FG_OK, src,
                                 "\"out\":\"%s\"", o.write_files ? o.out_dir : "");
    st = fg_carve_run(src, &o, &res);
    progress_done();
    if (g_audit)
        fg_audit_eventf(g_audit, FG_EV_SCAN_END, st, src,
                        "\"recovered\":%llu,\"bytes\":%llu,\"headers\":%llu,"
                        "\"report\":\"%s\"",
                        (unsigned long long)res.files_recovered,
                        (unsigned long long)res.bytes_recovered,
                        (unsigned long long)res.headers_seen, res.report_id);

    fill_meta(&meta, argc, argv);
    {
        fg_buf b;
        fg_report_scan_buf(&res, &meta, g_json ? FG_RPT_JSON : FG_RPT_TEXT, &b);
        if (g_json) fwrite(b.data, 1, b.len, stdout);
        else        printf("\n%s\n", b.data ? b.data : "");
        fg_buf_free(&b);
    }
    if (report && fg_report_scan(&res, &meta, fmt_from_path(report), report) == FG_OK && !g_json)
        printf("Report written to %s\n", report);

    fg_scan_result_free(&res);
    return st == FG_OK ? 0 : 1;
}


static int cmd_audit_verify(int argc, char **argv)
{
    const char *log = opt(argc, argv, "--log", g_audit_path);
    const char *keyhex = opt(argc, argv, "--key", NULL);
    fg_audit_verify v;
    uint8_t key[32];
    int klen = 0;
    fg_status st;

    if (keyhex) klen = fg_hex_decode(keyhex, key, sizeof key);
    st = fg_audit_verify_file(log, klen > 0 ? key : NULL,
                              klen > 0 ? (size_t)klen : 0, &v);
    if (g_json) {
        printf("{\"chain_ok\":%s,\"seal_checked\":%s,\"seal_ok\":%s,\"records\":%llu,"
               "\"first_bad_record\":%llu,\"head\":\"%s\",\"session\":\"%s\","
               "\"operator\":\"%s\",\"case\":\"%s\",\"message\":\"%s\"}\n",
               v.chain_ok ? "true" : "false", v.seal_checked ? "true" : "false",
               v.seal_ok ? "true" : "false", (unsigned long long)v.records,
               (unsigned long long)v.first_bad_record, v.head_hash, v.session_id,
               v.operator_name, v.case_id, v.message);
    } else {
        printf("\nAudit log : %s\n  records   : %llu in %llu session(s)\n  chain     : %s\n",
               log, (unsigned long long)v.records, (unsigned long long)v.sessions,
               v.chain_ok ? "INTACT" : "BROKEN");
        if (v.seal_checked)
            printf("  HMAC seal : %s\n", v.seal_ok ? "VERIFIED" : "INVALID");
        if (v.session_id[0]) printf("  session   : %s\n", v.session_id);
        if (v.operator_name[0]) printf("  operator  : %s\n", v.operator_name);
        if (v.case_id[0]) printf("  case      : %s\n", v.case_id);
        printf("  head      : %s\n  verdict   : %s\n\n", v.head_hash, v.message);
    }
    return st == FG_OK ? 0 : 1;
}

static int cmd_serve(int argc, char **argv)
{
    fg_server_opts o;
    memset(&o, 0, sizeof o);
    o.bind_addr = opt(argc, argv, "--bind", "127.0.0.1");
    o.port      = atoi(opt(argc, argv, "--port", "8787"));
    o.token     = opt(argc, argv, "--token", NULL);
    o.audit     = g_audit;
    if (fg_jobs_init(g_audit) != FG_OK) {
        fprintf(stderr, "error: cannot start the job manager\n");
        return 1;
    }
    {
        fg_status st = fg_server_run(&o);
        fg_jobs_shutdown();
        if (st != FG_OK) {
            fprintf(stderr, "error: cannot bind %s:%d (%s)\n",
                    o.bind_addr, o.port, fg_strerror(st));
            return 1;
        }
    }
    return 0;
}


static int cmd_selftest(void)
{
    int fails = 0;
#define CHECK(cond, what) do { \
        printf("  [%s] %s\n", (cond) ? " ok " : "FAIL", what); \
        if (!(cond)) fails++; \
    } while (0)

    printf("\nFORGE self test\n\n");


    {
        char hex[65];
        fg_sha256_hex("abc", 3, hex);
        CHECK(!strcmp(hex, "ba7816bf8f01cfea414140de5dae2223"
                           "b00361a396177a9cb410ff61f20015ad"), "SHA-256 (\"abc\")");
        fg_sha256_hex("", 0, hex);
        CHECK(!strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb924"
                           "27ae41e4649b934ca495991b7852b855"), "SHA-256 (empty)");
    }

    {
        uint8_t mac[32];
        char hex[65];
        fg_hmac_buf((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", 28, mac);
        fg_hex_encode(mac, 32, hex);
        CHECK(!strcmp(hex, "5bdcc146bf60754e6a042426089575c7"
                           "5a003f089d2739839dec58b964ec3843"), "HMAC-SHA256 (RFC 4231 #2)");
    }

    {
        fg_md5 c;
        uint8_t d[16];
        char hex[33];
        fg_md5_init(&c);
        fg_md5_update(&c, "abc", 3);
        fg_md5_final(&c, d);
        fg_hex_encode(d, 16, hex);
        CHECK(!strcmp(hex, "900150983cd24fb0d6963f7d28e17f72"), "MD5 (\"abc\")");
    }

    CHECK(fg_crc32(0, "123456789", 9) == 0xCBF43926u, "CRC-32 (check value)");


    {
        fg_rng r;
        uint8_t a[4096], b[4096];
        double h;
        fg_rng_init(&r);
        fg_rng_fill(&r, a, sizeof a);
        fg_rng_fill(&r, b, sizeof b);
        h = fg_shannon_entropy(a, sizeof a);
        CHECK(memcmp(a, b, sizeof a) != 0, "CSPRNG produces distinct blocks");
        CHECK(h > 7.5, "CSPRNG entropy > 7.5 bits/byte");
    }

    {
        const fg_method_def *d = fg_method_get(FG_M_DOD_3);
        uint8_t buf[64];
        fg_pattern_fill(d, 0, NULL, buf, sizeof buf, 0);
        CHECK(buf[0] == 0x00 && buf[63] == 0x00, "DoD pass 1 writes 0x00");
        fg_pattern_fill(d, 1, NULL, buf, sizeof buf, 0);
        CHECK(buf[0] == 0xFF && buf[63] == 0xFF, "DoD pass 2 writes the complement");
        CHECK(fg_method_get(FG_M_GUTMANN)->pass_count == 35, "Gutmann has 35 passes");
        CHECK(fg_method_parse("dod3") == FG_M_DOD_3, "method name parsing");
    }

    {
        uint8_t png[] = {
            0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A,
            0,0,0,13, 'I','H','D','R', 0,0,0,1, 0,0,0,1, 8,2,0,0,0, 0,0,0,0,
            0,0,0,0,  'I','E','N','D', 0,0,0,0 };
        const fg_sig *s = fg_sig_by_ext("png");
        int q = 0;
        uint64_t len;

        {
            uint32_t crc = fg_crc32(0, png + 12, 17);
            png[29] = (uint8_t)(crc >> 24); png[30] = (uint8_t)(crc >> 16);
            png[31] = (uint8_t)(crc >> 8);  png[32] = (uint8_t)crc;
            crc = fg_crc32(0, png + 37, 4);
            png[41] = (uint8_t)(crc >> 24); png[42] = (uint8_t)(crc >> 16);
            png[43] = (uint8_t)(crc >> 8);  png[44] = (uint8_t)crc;
        }
        len = s && s->validate ? s->validate(png, sizeof png, s, &q) : 0;
        CHECK(len == sizeof png, "PNG validator finds the exact length");
        CHECK(q == 3, "PNG chunk CRCs verify");
    }
    {

        uint8_t jpg[] = { 0xFF,0xD8, 0xFF,0xE0, 0x00,0x0E,
                          'J','F','I','F',0, 1,1,0,0,1,0,1, 0xFF,0xD9 };
        const fg_sig *s = fg_sig_by_ext("jpg");
        int q = 0;
        uint64_t len = s && s->validate ? s->validate(jpg, sizeof jpg, s, &q) : 0;
        CHECK(len == sizeof jpg, "JPEG validator walks segments to EOI");
    }
    {
        uint8_t bmp[54];
        const fg_sig *s = fg_sig_by_ext("bmp");
        int q = 0;
        uint64_t len;
        memset(bmp, 0, sizeof bmp);
        bmp[0] = 'B'; bmp[1] = 'M';
        bmp[2] = 54; 
        bmp[10] = 54;
        bmp[14] = 40;
        bmp[18] = 1; 
        bmp[22] = 1; 
        bmp[26] = 1; 
        bmp[28] = 24;
        len = s && s->validate ? s->validate(bmp, sizeof bmp, s, &q) : 0;
        CHECK(len == 54, "BMP validator reads bfSize");
    }
    
    {
        int n, hits = 0;
        const fg_sig *t = fg_sig_table(&n);
        fg_ac *ac = NULL;
        uint8_t blob[512];
        memset(blob, 0x5A, sizeof blob);
        memcpy(blob + 10, "\x89PNG\r\n\x1a\n", 8);
        memcpy(blob + 100, "\xFF\xD8\xFF", 3);
        memcpy(blob + 200, "PK\x03\x04", 4);
        memcpy(blob + 300, "%PDF-", 5);
        if (fg_ac_build(&ac, t, n, NULL) == FG_OK) {
    
            extern void fg_selftest_hit(void *, uint64_t, int);
            fg_ac_scan(ac, blob, sizeof blob, 0, fg_selftest_hit, &hits);
            fg_ac_free(ac);
        }
        CHECK(hits >= 4, "Aho-Corasick finds all four planted signatures");
    }
    
    {
        char tmp[4096], path[4200];
        fg_audit *a = NULL;
        fg_audit_verify v;
        uint8_t key[32];
        int i;
        fg_temp_dir(tmp, sizeof tmp);
        snprintf(path, sizeof path, "%s%cforge_selftest_audit.log", tmp, FG_PATH_SEP);
        fg_fs_remove(path);
        memset(key, 0x42, sizeof key);
        if (fg_audit_open(&a, path, key, sizeof key, "selftest", "SELFTEST") == FG_OK) {
            for (i = 0; i < 5; i++)
                fg_audit_eventf(a, FG_EV_CUSTODY, FG_OK, "subject", "\"i\":%d", i);
            fg_audit_close(a);
        }
        CHECK(fg_audit_verify_file(path, key, sizeof key, &v) == FG_OK &&
              v.chain_ok && v.seal_ok, "audit chain verifies and the seal matches");
    
        {
            FILE *f = fopen(path, "r+b");
            if (f) {
                char line[4096];
                long pos = 0;
                while (fgets(line, sizeof line, f)) {
                    char *p = strstr(line, "\"i\":2");
                    if (p) {
                        fseek(f, pos + (p - line) + 4, SEEK_SET);
                        fputc('9', f);
                        break;
                    }
                    pos = ftell(f);
                }
                fclose(f);
            }
        }
        CHECK(fg_audit_verify_file(path, key, sizeof key, &v) != FG_OK && !v.chain_ok,
              "a single altered byte breaks the chain");
        fg_fs_remove(path);
    }
    
    {
        char tmp[4096], path[4200];
        FILE *f;
        fg_drive_opts o;
        fg_drive_result r;
        void *a = fg_aligned_alloc(4096);
        CHECK(a != NULL && ((size_t)(uintptr_t)a % FG_IO_ALIGN) == 0,
              "aligned allocator returns block-aligned memory");
        fg_aligned_free(a);

        fg_temp_dir(tmp, sizeof tmp);
        snprintf(path, sizeof path, "%s%cforge_selftest_image.bin", tmp, FG_PATH_SEP);
        f = fopen(path, "wb");
        if (f) {
            int i;
            for (i = 0; i < 2048; i++) fputs("RECOVERABLE_TEXT", f);  
            fclose(f);
        }
        fg_drive_opts_default(&o);
        o.method        = FG_M_DOD_3;
        o.verify        = FG_VERIFY_FULL;
        o.confirm_token = "ERASE";
        o.use_firmware  = 0;
        o.trim_after    = 0;
        fg_drive_erase(path, &o, &r);
        CHECK(r.status == FG_OK, "drive eraser completes on an image file");
        CHECK(r.passes_done == 3, "all three passes were written");
        CHECK(r.bad_sectors == 0, "no spurious unwritable sectors");
        CHECK(r.verify.passed && r.verify.coverage_percent > 99.9,
              "full read-back verification passes at 100% coverage");
        
        {
            FILE *g = fopen(path, "rb");
            char buf[4096];
            size_t n2, found = 0;
            if (g) {
                while ((n2 = fread(buf, 1, sizeof buf, g)) > 0) {
                    size_t k;
                    for (k = 0; k + 16 <= n2; k++)
                        if (!memcmp(buf + k, "RECOVERABLE_TEXT", 16)) found++;
                }
                fclose(g);
            }
            CHECK(found == 0, "no plaintext survives the overwrite");
        }
        fg_fs_remove(path);
    }

    
    {
        char tmp[4096], path[4200];
        FILE *f;
        fg_file_opts o;
        fg_file_result r;
        const char *p;
        fg_temp_dir(tmp, sizeof tmp);
        snprintf(path, sizeof path, "%s%cforge_selftest_target.bin", tmp, FG_PATH_SEP);
        f = fopen(path, "wb");
        if (f) {
            int i;
            for (i = 0; i < 4096; i++) fputs("SENSITIVE", f);
            fclose(f);
        }
        fg_file_opts_default(&o);
        o.method = FG_M_DOD_3;
        o.verify = FG_VERIFY_FULL;
        p = path;
        fg_file_erase_paths(&p, 1, &o, &r);
        CHECK(r.files_erased == 1, "file eraser erased the target");
        CHECK(r.records && r.records->verified, "overwrite verified before unlink");
        CHECK(!fg_fs_exists(path), "target no longer exists");
        fg_file_result_free(&r);
    }

    printf("\n  %s (%d failure%s)\n\n", fails ? "SELF TEST FAILED" : "all checks passed",
           fails, fails == 1 ? "" : "s");
#undef CHECK
    return fails ? 1 : 0;
}

void fg_selftest_hit(void *user, uint64_t off, int sig);
void fg_selftest_hit(void *user, uint64_t off, int sig)
{
    FG_UNUSED(off); FG_UNUSED(sig);
    (*(int *)user)++;
}


int main(int argc, char **argv)
{
    int rc = 0;
    const char *cmd;

    if (argc < 2 || flag(argc, argv, "--help") || flag(argc, argv, "-h")) {
        usage();
        return argc < 2 ? 2 : 0;
    }
    if (flag(argc, argv, "--version")) {
        printf("%s %s\n", FG_PRODUCT, FG_VERSION_STR);
        return 0;
    }
    g_json  = flag(argc, argv, "--json");
    g_quiet = flag(argc, argv, "--quiet");
    if (flag(argc, argv, "--verbose")) fg_log_set_level(FG_LOG_DEBUG);
    if (g_json || g_quiet) fg_log_set_level(FG_LOG_ERROR);
    snprintf(g_audit_path, sizeof g_audit_path, "%s",
             opt(argc, argv, "--audit-log", "forge-audit.log"));

    cmd = argv[1];


    if (!strcmp(cmd, "erase") || !strcmp(cmd, "recover") || !strcmp(cmd, "serve")) {
        const char *keyhex = opt(argc, argv, "--audit-key", NULL);
        uint8_t key[32];
        int klen = keyhex ? fg_hex_decode(keyhex, key, sizeof key) : 0;
        if (fg_audit_open(&g_audit, g_audit_path, klen > 0 ? key : NULL,
                          klen > 0 ? (size_t)klen : 0,
                          opt(argc, argv, "--operator", ""),
                          opt(argc, argv, "--case", "")) != FG_OK) {
            fprintf(stderr, "warning: cannot write the audit log at %s; "
                            "continuing without an audit trail\n", g_audit_path);
        }
    }

    if      (!strcmp(cmd, "devices")) { banner(); rc = cmd_devices(); }
    else if (!strcmp(cmd, "methods")) { rc = cmd_methods(); }
    else if (!strcmp(cmd, "types"))   { rc = cmd_types(); }
    else if (!strcmp(cmd, "parts"))   { rc = cmd_parts(argc, argv); }
    else if (!strcmp(cmd, "selftest")){ rc = cmd_selftest(); }
    else if (!strcmp(cmd, "serve"))   { rc = cmd_serve(argc, argv); }
    else if (!strcmp(cmd, "recover")) { banner(); rc = cmd_recover(argc, argv); }
    else if (!strcmp(cmd, "erase")) {
        const char *sub = argc > 2 ? argv[2] : "";
        banner();
        if      (!strcmp(sub, "drive"))     rc = cmd_erase_drive(argc, argv);
        else if (!strcmp(sub, "file") ||
                 !strcmp(sub, "files"))     rc = cmd_erase_file(argc, argv);
        else if (!strcmp(sub, "freespace")) rc = cmd_erase_freespace(argc, argv);
        else { fprintf(stderr, "error: erase needs drive | file | freespace\n"); rc = 2; }
    }
    else if (!strcmp(cmd, "audit")) {
        const char *sub = argc > 2 ? argv[2] : "";
        if (!strcmp(sub, "verify")) rc = cmd_audit_verify(argc, argv);
        else { fprintf(stderr, "error: audit needs verify\n"); rc = 2; }
    }
    else {
        fprintf(stderr, "error: unknown command '%s'\n\n", cmd);
        usage();
        rc = 2;
    }

    if (g_audit) fg_audit_close(g_audit);
    return rc;
}
