/* kv_erase.h - Module 1 (Secure Drive Eraser) and Module 2 (Secure File and
 * Folder Eraser) share the same pattern engine and verification machinery,
 * so they share this header.
 */
#ifndef KV_ERASE_H
#define KV_ERASE_H

#include "kv_common.h"
#include "kv_platform.h"
#include "kv_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*  Sanitization methods                                                      */
/* ========================================================================== */

typedef enum {
    KV_M_ZERO = 0,        /* 1 pass 0x00              - NIST 800-88 Clear     */
    KV_M_ONES,            /* 1 pass 0xFF                                      */
    KV_M_RANDOM,          /* 1 pass CSPRNG            - NIST 800-88 Clear     */
    KV_M_NIST_CLEAR,      /* 1 random pass + full verify                      */
    KV_M_NIST_PURGE,      /* firmware sanitize, fallback to 1 random + verify */
    KV_M_DOD_3,           /* DoD 5220.22-M   (3 passes)                       */
    KV_M_DOD_7,           /* DoD 5220.22-M ECE (7 passes)                     */
    KV_M_VSITR,           /* German BSI-VSITR (7 passes)                      */
    KV_M_HMG_IS5,         /* HMG Infosec Standard 5 Enhanced (3 passes)       */
    KV_M_GOST,            /* GOST R 50739-95 (2 passes)                       */
    KV_M_SCHNEIER,        /* Schneier (7 passes)                              */
    KV_M_GUTMANN,         /* Gutmann (35 passes)                              */
    KV_M_CRYPTO_ERASE,    /* SED / NVMe crypto erase only                     */
    KV_M__COUNT
} kv_method;

typedef enum {
    KV_PAT_FIXED,      /* repeat one byte                                     */
    KV_PAT_TRIPLE,     /* repeat a 3-byte group (Gutmann)                     */
    KV_PAT_RANDOM,     /* CSPRNG                                              */
    KV_PAT_COMPLEMENT  /* bitwise complement of the previous pass             */
} kv_pattern_kind;

typedef struct {
    kv_pattern_kind kind;
    uint8_t         bytes[3];
    int             verify;   /* verify this pass immediately after writing   */
} kv_pass;

typedef struct {
    const char    *name;        /* "DoD 5220.22-M"                            */
    const char    *standard;    /* citation shown on the certificate          */
    const char    *cli_name;    /* "dod3"                                     */
    int            pass_count;
    const kv_pass *passes;
    int            firmware_first; /* try ATA/NVMe sanitize before overwriting */
    int            final_verify;   /* full read-back after the last pass       */
} kv_method_def;

const kv_method_def *kv_method_get(kv_method m);
kv_method            kv_method_parse(const char *cli_name);  /* -1 if unknown */
void                 kv_method_list(void (*emit)(void *, const kv_method_def *), void *user);

/* ========================================================================== */
/*  Verification                                                              */
/* ========================================================================== */

typedef enum {
    KV_VERIFY_NONE = 0,
    KV_VERIFY_SAMPLE,   /* statistically significant random sample (default)  */
    KV_VERIFY_FULL      /* read every byte back                               */
} kv_verify_mode;

typedef struct {
    kv_verify_mode mode;
    uint64_t       bytes_checked;
    uint64_t       sectors_checked;
    uint64_t       mismatches;
    double         entropy;            /* for random-pattern passes           */
    double         coverage_percent;
    char           digest_hex[65];     /* SHA-256 over the verified sample    */
    int            passed;
} kv_verify_result;

/* ========================================================================== */
/*  Module 1: drive erasure                                                   */
/* ========================================================================== */

typedef struct {
    kv_method      method;
    kv_verify_mode verify;
    int            allow_system_disk;   /* must be explicitly set             */
    int            dry_run;
    int            use_firmware;        /* honour firmware_first if available */
    int            trim_after;          /* issue TRIM/discard after overwrite */
    uint64_t       block_size;          /* default 4 MiB                      */
    const char    *confirm_token;       /* must equal serial or "CONFIRM"     */
    const char    *operator_name;
    const char    *case_id;
    kv_progress    progress;
} kv_drive_opts;

typedef struct {
    char             device_id[64];
    char             model[80];
    char             serial[80];
    uint64_t         size_bytes;
    uint32_t         sector_size;
    kv_method        method;
    char             method_name[64];
    char             standard[96];
    int              passes_done;
    int              passes_total;
    uint64_t         bytes_written;
    uint64_t         bad_sectors;
    uint64_t         bad_sector_first;
    double           seconds;
    double           throughput_mbs;
    int              firmware_used;
    char             firmware_detail[160];
    kv_verify_result verify;
    char             started_at[32];
    char             finished_at[32];
    kv_status        status;
    char             message[256];
    char             report_id[33];
} kv_drive_result;

void      kv_drive_opts_default(kv_drive_opts *o);
kv_status kv_drive_erase(const char *device_path, const kv_drive_opts *o,
                         kv_drive_result *res);

/* ========================================================================== */
/*  Module 2: file and folder erasure                                         */
/* ========================================================================== */

typedef struct {
    kv_method      method;
    kv_verify_mode verify;
    int            recursive;
    int            remove_metadata;   /* names, timestamps, ADS, xattrs       */
    int            wipe_slack;        /* wipe the file's cluster slack        */
    int            remove_empty_dirs;
    int            follow_symlinks;
    int            dry_run;
    int            keep_going;        /* do not stop at the first failure     */
    const char    *include_glob;      /* comma separated, NULL = everything   */
    const char    *exclude_glob;
    uint64_t       max_size;          /* 0 = no limit                         */
    const char    *operator_name;
    const char    *case_id;
    kv_progress    progress;
} kv_file_opts;

typedef struct kv_file_record {
    char      path[4096];
    uint64_t  size;
    int       passes;
    int       renames;
    int       alt_streams_removed;
    int       xattrs_removed;
    uint64_t  slack_bytes;
    int       verified;
    kv_status status;
    char      message[160];
    char      sha256_before[65];
    struct kv_file_record *next;
} kv_file_record;

typedef struct {
    kv_method       method;
    char            method_name[64];
    uint64_t        files_total;
    uint64_t        files_erased;
    uint64_t        files_failed;
    uint64_t        dirs_removed;
    uint64_t        bytes_erased;
    uint64_t        slack_bytes;
    uint64_t        streams_removed;
    uint64_t        xattrs_removed;
    double          seconds;
    kv_file_record *records;      /* linked list, owned by the result         */
    char            started_at[32];
    char            finished_at[32];
    kv_status       status;
    char            report_id[33];
} kv_file_result;

void      kv_file_opts_default(kv_file_opts *o);
kv_status kv_file_erase_paths(const char *const *paths, int npaths,
                              const kv_file_opts *o, kv_file_result *res);
void      kv_file_result_free(kv_file_result *res);

/* Free-space wiping: fills the unallocated space of a volume so that
 * previously deleted file content becomes unrecoverable. */
typedef struct {
    uint64_t bytes_written;
    uint64_t mft_records_wiped;   /* small-file MFT resident space (NTFS)     */
    double   seconds;
    double   free_before_gb;
    double   free_after_gb;
} kv_freespace_result;

kv_status kv_wipe_free_space(const char *volume_path, kv_method m,
                             int wipe_directory_entries,
                             const kv_progress *pg, kv_freespace_result *res);

/* Shared pattern generator: fills `buf` for pass `pass_index` of method `m`.
 * `prev` may be NULL; it is only used by KV_PAT_COMPLEMENT passes. */
void kv_pattern_fill(const kv_method_def *def, int pass_index, kv_rng *rng,
                     uint8_t *buf, size_t n, uint64_t offset);
/* Returns 1 when the pass content is deterministic and can be re-generated
 * for byte-exact verification; 0 for random passes (entropy check instead). */
int  kv_pattern_deterministic(const kv_method_def *def, int pass_index);

#ifdef __cplusplus
}
#endif
#endif /* KV_ERASE_H */
