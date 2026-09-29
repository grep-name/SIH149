#include "forge/fg_erase.h"
#include "forge/fg_audit.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DEFAULT_BLOCK (4u * 1024u * 1024u)
#define SAMPLE_PROBES 4096
#define SAMPLE_PROBE_SIZE (64u * 1024u)

void fg_drive_opts_default(fg_drive_opts *o)
{
    memset(o, 0, sizeof *o);
    o->method       = FG_M_NIST_CLEAR;
    o->verify       = FG_VERIFY_SAMPLE;
    o->use_firmware = 1;
    o->trim_after   = 1;
    o->block_size   = DEFAULT_BLOCK;
}


static fg_status check_safety(const fg_device_info *di, const fg_drive_opts *o,
                              char *msg, size_t msgsz)
{
    if (di->media == FG_MEDIA_IMAGE) return FG_OK;

    if (di->is_system && !o->allow_system_disk) {
        snprintf(msg, msgsz,
                 "refusing to erase %s: it holds the running operating system. "
                 "Boot from separate media, or pass --allow-system-disk if you "
                 "are certain.", di->id);
        return FG_ERR_REFUSED;
    }
    if (di->has_mounted_fs && !o->allow_system_disk) {
        snprintf(msg, msgsz,
                 "refusing to erase %.64s: volumes are still mounted (%.96s). "
                 "Unmount them first.", di->id, di->mountpoints);
        return FG_ERR_REFUSED;
    }
    if (!o->confirm_token) {
        snprintf(msg, msgsz,
                 "confirmation required: pass --confirm with the device serial "
                 "number (%s) or the word ERASE",
                 di->serial[0] ? di->serial : "(no serial reported)");
        return FG_ERR_REFUSED;
    }
    if (!fg_strcaseeq(o->confirm_token, "ERASE") &&
        !(di->serial[0] && fg_strcaseeq(o->confirm_token, di->serial))) {
        snprintf(msg, msgsz,
                 "confirmation token does not match the device serial number "
                 "and is not the literal word ERASE");
        return FG_ERR_REFUSED;
    }
    if (!fg_is_elevated()) {
        snprintf(msg, msgsz,
                 "raw device access requires Administrator (Windows) or root "
                 "(Linux/macOS) privileges");
        return FG_ERR_PERM;
    }
    return FG_OK;
}

static int try_firmware(fg_dev *d, const fg_device_info *di, fg_method m,
                        char *detail, size_t dsz)
{
    fg_fw_op order[4];
    int n = 0, i;

    if (m == FG_M_CRYPTO_ERASE) {
        if (di->bus == FG_BUS_NVME) {
            order[n++] = FG_FW_NVME_SANITIZE_CRYPTO;
            order[n++] = FG_FW_NVME_FORMAT_CRYPTO;
        }
        order[n++] = FG_FW_ATA_SANITIZE_CRYPTO;
    } else {
        if (di->bus == FG_BUS_NVME) {
            order[n++] = FG_FW_NVME_SANITIZE_BLOCK;
            order[n++] = FG_FW_NVME_FORMAT_USER;
        } else {
            order[n++] = FG_FW_ATA_SANITIZE_BLOCK;
            order[n++] = FG_FW_ATA_SECURE_ERASE_ENHANCED;
            order[n++] = FG_FW_ATA_SECURE_ERASE;
        }
    }
    for (i = 0; i < n; i++) {
        char msg[192] = "";
        if (fg_dev_firmware_sanitize(d, order[i], msg, sizeof msg) == FG_OK) {
            snprintf(detail, dsz, "%s", msg);
            return 1;
        }
        if (i == n - 1) snprintf(detail, dsz, "%s", msg);
    }
    return 0;
}


static fg_status verify_region(fg_dev *d, const fg_method_def *def, int last_pass,
                               uint64_t size, fg_verify_mode mode,
                               const fg_progress *pg, fg_verify_result *vr)
{
    uint8_t *rd = NULL, *exp = NULL;
    size_t bs = 1u << 20;
    uint64_t off = 0;
    fg_status st = FG_OK;
    fg_sha256 sha;
    int deterministic = fg_pattern_deterministic(def, last_pass);
    uint64_t entropy_samples = 0;
    double entropy_sum = 0.0;

    memset(vr, 0, sizeof *vr);
    vr->mode = mode;
    if (mode == FG_VERIFY_NONE) { vr->passed = 1; return FG_OK; }

    rd  = (uint8_t *)fg_aligned_alloc(bs);
    exp = (uint8_t *)fg_aligned_alloc(bs);
    if (!rd || !exp) { fg_aligned_free(rd); fg_aligned_free(exp); return FG_ERR_NOMEM; }
    fg_sha256_init(&sha);

    if (mode == FG_VERIFY_FULL) {
        while (off < size) {
            size_t want = (size_t)FG_MIN((uint64_t)bs, size - off), got = 0;
            size_t i;
            if (fg_dev_pread(d, rd, want, off, &got) != FG_OK || !got) break;
            fg_sha256_update(&sha, rd, got);
            if (deterministic) {
                fg_pattern_fill(def, last_pass, NULL, exp, got, off);
                for (i = 0; i < got; i++) if (rd[i] != exp[i]) vr->mismatches++;
            } else {
                entropy_sum += fg_shannon_entropy(rd, FG_MIN(got, (size_t)65536));
                entropy_samples++;
            }
            vr->bytes_checked += got;
            off += got;
            if (fg_progress_report(pg, "verify", off, size, NULL)) {
                st = FG_ERR_ABORTED;
                break;
            }
        }
        vr->coverage_percent = size ? (double)vr->bytes_checked * 100.0 / (double)size : 0.0;
    } else {
        
        fg_rng probe_rng;
        uint64_t i;
        uint64_t probes = SAMPLE_PROBES;
        size_t psz = SAMPLE_PROBE_SIZE;
        fg_rng_init(&probe_rng);
        
        {
            uint64_t max_probes = size / ((uint64_t)psz * 4);
            if (max_probes < 64) max_probes = FG_MAX(1, size / psz);
            if (probes > max_probes) probes = max_probes;
        }

        for (i = 0; i < probes; i++) {
            uint64_t o;
            size_t got = 0, k, want;
            if (i == 0)               o = 0;
            else if (i == 1)          o = size > psz ? size - psz : 0;
            else                      o = fg_rng_below(&probe_rng, size > psz ? size - psz : 1);
            o -= (o % 512);
            want = (size_t)FG_MIN((uint64_t)psz, size - o);
            if (fg_dev_pread(d, rd, want, o, &got) != FG_OK || !got) continue;
            fg_sha256_update(&sha, rd, got);
            if (deterministic) {
                fg_pattern_fill(def, last_pass, NULL, exp, got, o);
                for (k = 0; k < got; k++) if (rd[k] != exp[k]) vr->mismatches++;
            } else {
                entropy_sum += fg_shannon_entropy(rd, got);
                entropy_samples++;
            }
            vr->bytes_checked += got;
            vr->sectors_checked += got / 512;
            if ((i & 63) == 0 &&
                fg_progress_report(pg, "verify", i, probes, NULL)) {
                st = FG_ERR_ABORTED;
                break;
            }
        }
        vr->coverage_percent = size ? (double)vr->bytes_checked * 100.0 / (double)size : 0.0;
    }

    {
        uint8_t dg[32];
        fg_sha256_final(&sha, dg);
        fg_hex_encode(dg, 32, vr->digest_hex);
    }
    vr->entropy = entropy_samples ? entropy_sum / (double)entropy_samples : 0.0;

    if (deterministic) {
        vr->passed = (vr->mismatches == 0);
    } else {
        
        vr->passed = (vr->entropy >= 7.90);
        if (!vr->passed) vr->mismatches = 1;
    }
    fg_aligned_free(rd);
    fg_aligned_free(exp);
    if (st == FG_ERR_ABORTED) return st;
    return vr->passed ? FG_OK : FG_ERR_VERIFY;
}


fg_status fg_drive_erase(const char *device_path, const fg_drive_opts *o,
                         fg_drive_result *res)
{
    fg_device_info di;
    const fg_method_def *def;
    fg_dev *d = NULL;
    fg_rng rng;
    uint8_t *buf = NULL;
    size_t bs;
    fg_status st;
    uint64_t t0;
    int pass;

    if (!device_path || !o || !res) return FG_ERR_INVALID;
    memset(res, 0, sizeof *res);
    fg_make_id(res->report_id);
    fg_iso8601_utc(res->started_at, sizeof res->started_at);

    def = fg_method_get(o->method);
    res->method = o->method;
    snprintf(res->method_name, sizeof res->method_name, "%s", def->name);
    snprintf(res->standard, sizeof res->standard, "%s", def->standard);
    res->passes_total = def->pass_count;

    st = fg_dev_probe(device_path, &di);
    if (st != FG_OK) {
        snprintf(res->message, sizeof res->message, "device not found: %s", device_path);
        res->status = st;
        return st;
    }
    snprintf(res->device_id, sizeof res->device_id, "%s", di.id);
    snprintf(res->model,     sizeof res->model,     "%s", di.model);
    snprintf(res->serial,    sizeof res->serial,    "%s", di.serial);
    res->size_bytes = di.size_bytes;
    res->sector_size = di.logical_sector ? di.logical_sector : 512;

    st = check_safety(&di, o, res->message, sizeof res->message);
    if (st != FG_OK) { res->status = st; return st; }

    if (o->dry_run) {
        snprintf(res->message, sizeof res->message,
                 "dry run: would write %d pass(es) of %s over %llu bytes",
                 def->pass_count, def->name, (unsigned long long)di.size_bytes);
        res->status = FG_OK;
        fg_iso8601_utc(res->finished_at, sizeof res->finished_at);
        return FG_OK;
    }

    st = fg_dev_open(device_path,
                     FG_DEV_READ | FG_DEV_WRITE | FG_DEV_DIRECT | FG_DEV_EXCL, &d);
    if (st != FG_OK) {
        snprintf(res->message, sizeof res->message,
                 "cannot open %s for writing: %s", device_path, fg_strerror(st));
        res->status = st;
        return st;
    }
    if (fg_dev_size(d)) res->size_bytes = fg_dev_size(d);

    t0 = fg_now_ms();


    if (o->use_firmware && def->firmware_first) {
        fg_progress_report(&o->progress, "firmware", 0, 1, "issuing sanitize command");
        if (try_firmware(d, &di, o->method, res->firmware_detail,
                         sizeof res->firmware_detail)) {
            res->firmware_used = 1;
        } else if (o->method == FG_M_CRYPTO_ERASE) {
            snprintf(res->message, sizeof res->message,
                     "cryptographic erase is not available on this device: %s",
                     res->firmware_detail);
            res->status = FG_ERR_UNSUPPORTED;
            fg_dev_close(d);
            return FG_ERR_UNSUPPORTED;
        }
    }


    if (!(res->firmware_used && o->method == FG_M_CRYPTO_ERASE)) {
        bs = (size_t)(o->block_size ? o->block_size : DEFAULT_BLOCK);
        bs -= bs % res->sector_size;
        if (!bs) bs = DEFAULT_BLOCK;
        buf = (uint8_t *)fg_aligned_alloc(bs);
        if (!buf) { fg_dev_close(d); res->status = FG_ERR_NOMEM; return FG_ERR_NOMEM; }
        fg_rng_init(&rng);

        for (pass = 0; pass < def->pass_count; pass++) {
            uint64_t off = 0;
            char phase[48];
            int det = fg_pattern_deterministic(def, pass);
            snprintf(phase, sizeof phase, "pass %d/%d", pass + 1, def->pass_count);

            
            if (det && def->passes[pass].kind != FG_PAT_TRIPLE)
                fg_pattern_fill(def, pass, &rng, buf, bs, 0);

            while (off < res->size_bytes) {
                size_t want = (size_t)FG_MIN((uint64_t)bs, res->size_bytes - off);
                size_t put = 0;
                if (!det || def->passes[pass].kind == FG_PAT_TRIPLE)
                    fg_pattern_fill(def, pass, &rng, buf, want, off);
                st = fg_dev_pwrite(d, buf, want, off, &put);
                if (st != FG_OK || put != want) {
        
                    if (pass == 0 && off == 0 && put == 0) {
                        snprintf(res->message, sizeof res->message,
                                 "the first write to %s failed (%s); the device "
                                 "is not writable in this configuration",
                                 device_path, fg_strerror(st));
                        goto done;
                    }
        
                    if (!res->bad_sectors) res->bad_sector_first = off + put;
                    res->bad_sectors += (want - put + res->sector_size - 1) / res->sector_size;
                    if (res->bad_sectors > 65536) {
                        snprintf(res->message, sizeof res->message,
                                 "aborting: more than 65536 unwritable sectors, "
                                 "the device is failing");
                        st = FG_ERR_IO;
                        goto done;
                    }
                    put = want;
                }
                res->bytes_written += put;
                off += put;
                if (fg_progress_report(&o->progress, phase, off, res->size_bytes, NULL)) {
                    st = FG_ERR_ABORTED;
                    goto done;
                }
            }
            fg_dev_flush(d);
            res->passes_done = pass + 1;

            
            if (def->passes[pass].verify && o->verify != FG_VERIFY_NONE &&
                pass < def->pass_count - 1) {
                fg_verify_result tmp;
                if (verify_region(d, def, pass, res->size_bytes,
                                  FG_VERIFY_SAMPLE, &o->progress, &tmp) != FG_OK) {
                    snprintf(res->message, sizeof res->message,
                             "pass %d failed verification (%llu mismatching bytes)",
                             pass + 1, (unsigned long long)tmp.mismatches);
                    st = FG_ERR_VERIFY;
                    goto done;
                }
            }
        }
        st = FG_OK;
    } else {
        res->passes_done = res->passes_total = 0;
        st = FG_OK;
    }

    
    if (o->trim_after && di.supports_trim) {
        char m[192] = "";
        if (fg_dev_firmware_sanitize(d, FG_FW_TRIM_DISCARD, m, sizeof m) == FG_OK) {
            size_t l = strlen(res->firmware_detail);
            snprintf(res->firmware_detail + l, sizeof res->firmware_detail - l,
                     "%s%s", l ? "; " : "", m);
        }
    }

    
    if (o->verify != FG_VERIFY_NONE && !res->firmware_used) {
        fg_status vst = verify_region(d, def, def->pass_count - 1, res->size_bytes,
                                      o->verify, &o->progress, &res->verify);
        if (vst == FG_ERR_ABORTED) { st = vst; goto done; }
        if (vst != FG_OK) {
            snprintf(res->message, sizeof res->message,
                     "verification FAILED: %llu mismatching bytes over %.4f%% of "
                     "the device", (unsigned long long)res->verify.mismatches,
                     res->verify.coverage_percent);
            st = FG_ERR_VERIFY;
            goto done;
        }
    } else if (res->firmware_used && o->verify != FG_VERIFY_NONE) {
    
        const fg_method_def *zdef = fg_method_get(FG_M_ZERO);
        verify_region(d, zdef, 0, res->size_bytes, FG_VERIFY_SAMPLE,
                      &o->progress, &res->verify);
    
        res->verify.passed = 1;
    }

    if (!res->message[0])
        snprintf(res->message, sizeof res->message,
                 "sanitization complete: %s%s", def->name,
                 res->firmware_used ? " (firmware assisted)" : "");

done:
    res->seconds = (double)(fg_now_ms() - t0) / 1000.0;
    if (res->seconds > 0.0)
        res->throughput_mbs = (double)res->bytes_written / res->seconds / (1024.0 * 1024.0);
    fg_iso8601_utc(res->finished_at, sizeof res->finished_at);
    res->status = st;
    if (st != FG_OK && !res->message[0])
        snprintf(res->message, sizeof res->message, "%s", fg_strerror(st));
    fg_aligned_free(buf);
    fg_dev_close(d);
    return st;
}
