/* fg_erase.h - Module 1 (Secure Drive Eraser) and Module 2 (Secure File and
 * Folder Eraser) share the same pattern engine and verification machinery,
 * so they share this header.
 */
#ifndef FG_ERASE_H
#define FG_ERASE_H

#include "fg_common.h"
#include "fg_platform.h"
#include "fg_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*  Sanitization methods                                                      */
/* ========================================================================== */

typedef enum {
    FG_M_ZERO = 0,        /* 1 pass 0x00              - NIST 800-88 Clear     */
    FG_M_ONES,            /* 1 pass 0xFF                                      */
    FG_M_RANDOM,          /* 1 pass CSPRNG            - NIST 800-88 Clear     */
    FG_M_NIST_CLEAR,      /* 1 random pass + full verify                      */
    FG_M_NIST_PURGE,      /* firmware sanitize, fallback to 1 random + verify */
    FG_M_DOD_3,           /* DoD 5220.22-M   (3 passes)                       */
    FG_M_DOD_7,           /* DoD 5220.22-M ECE (7 passes)                     */
    FG_M_VSITR,           /* German BSI-VSITR (7 passes)                      */
    FG_M_HMG_IS5,         /* HMG Infosec Standard 5 Enhanced (3 passes)       */
    FG_M_GOST,            /* GOST R 50739-95 (2 passes)                       */
    FG_M_SCHNEIER,        /* Schneier (7 passes)                              */
    FG_M_GUTMANN,         /* Gutmann (35 passes)                              */
    FG_M_CRYPTO_ERASE,    /* SED / NVMe crypto erase only                     */
    FG_M__COUNT
} fg_method;

typedef enum {
    FG_PAT_FIXED,      /* repeat one byte                                     */
    FG_PAT_TRIPLE,     /* repeat a 3-byte group (Gutmann)                     */
    FG_PAT_RANDOM,     /* CSPRNG                                              */
    FG_PAT_COMPLEMENT  /* bitwise complement of the previous pass             */
} fg_pattern_kind;

typedef struct {
    fg_pattern_kind kind;
    uint8_t         bytes[3];
    int             verify;   /* verify this pass immediately after writing   */
} fg_pass;

typedef struct {
    const char    *name;        /* "DoD 5220.22-M"                            */
    const char    *standard;    /* citation shown on the certificate          */
    const char    *cli_name;    /* "dod3"                                     */
    int            pass_count;
    const fg_pass *passes;
    int            firmware_first; /* try ATA/NVMe sanitize before overwriting */
    int            final_verify;   /* full read-back after the last pass       */
} fg_method_def;

const fg_method_def *fg_method_get(fg_method m);
fg_method            fg_method_parse(const char *cli_name);  /* -1 if unknown */
void                 fg_method_list(void (*emit)(void *, const fg_method_def *), void *user);

/* ========================================================================== */
/*  Verification                                                              */
/* ========================================================================== */

typedef enum {
    FG_VERIFY_NONE = 0,
    FG_VERIFY_SAMPLE,   /* statistically significant random sample (default)  */
    FG_VERIFY_FULL      /* read every byte back                               */
} fg_verify_mode;

typedef struct {
    fg_verify_mode mode;
    uint64_t       bytes_checked;
    uint64_t       sectors_checked;
    uint64_t       mismatches;
    double         entropy;            /* for random-pattern passes           */
    double         coverage_percent;
    char           digest_hex[65];     /* SHA-256 over the verified sample    */
    int            passed;
} fg_verify_result;

/* ========================================================================== */
/*  Module 1: drive erasure                                                   */
/* ========================================================================== */

typedef struct {
    fg_method      method;
    fg_verify_mode verify;
    int            allow_system_disk;   /* must be explicitly set             */
    int            dry_run;
    int            use_firmware;        /* honour firmware_first if available */
    int            trim_after;          /* issue TRIM/discard after overwrite */
    uint64_t       block_size;          /* default 4 MiB                      */
    const char    *confirm_token;       /* must equal serial or "CONFIRM"     */
    const char    *operator_name;
    const char    *case_id;
    fg_progress    progress;
} fg_drive_opts;

typedef struct {
    char             device_id[64];
    char             model[80];
    char             serial[80];
    uint64_t         size_bytes;
    uint32_t         sector_size;
    fg_method        method;
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
    fg_verify_result verify;
    char             started_at[32];
    char             finished_at[32];
    fg_status        status;
    char             message[256];
    char             report_id[33];
} fg_drive_result;

void      fg_drive_opts_default(fg_drive_opts *o);
fg_status fg_drive_erase(const char *device_path, const fg_drive_opts *o,
                         fg_drive_result *res);

/* ========================================================================== */
/*  Module 2: file and folder erasure                                         */
/* ========================================================================== */

typedef struct {
    fg_method      method;
    fg_verify_mode verify;
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
    fg_progress    progress;
} fg_file_opts;

typedef struct fg_file_record {
    char      path[4096];
    uint64_t  size;
    int       passes;
    int       renames;
    int       alt_streams_removed;
    int       xattrs_removed;
    uint64_t  slack_bytes;
    int       verified;
    fg_status status;
    char      message[160];
    char      sha256_before[65];
    struct fg_file_record *next;
} fg_file_record;

typedef struct {
    fg_method       method;
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
    fg_file_record *records;      /* linked list, owned by the result         */
    char            started_at[32];
    char            finished_at[32];
    fg_status       status;
    char            report_id[33];
} fg_file_result;

void      fg_file_opts_default(fg_file_opts *o);
fg_status fg_file_erase_paths(const char *const *paths, int npaths,
                              const fg_file_opts *o, fg_file_result *res);
void      fg_file_result_free(fg_file_result *res);

/* Free-space wiping: fills the unallocated space of a volume so that
 * previously deleted file content becomes unrecoverable. */
typedef struct {
    uint64_t bytes_written;
    uint64_t mft_records_wiped;   /* small-file MFT resident space (NTFS)     */
    double   seconds;
    double   free_before_gb;
    double   free_after_gb;
} fg_freespace_result;

fg_status fg_wipe_free_space(const char *volume_path, fg_method m,
                             int wipe_directory_entries,
                             const fg_progress *pg, fg_freespace_result *res);

/* Shared pattern generator: fills `buf` for pass `pass_index` of method `m`.
 * `prev` may be NULL; it is only used by FG_PAT_COMPLEMENT passes. */
void fg_pattern_fill(const fg_method_def *def, int pass_index, fg_rng *rng,
                     uint8_t *buf, size_t n, uint64_t offset);
/* Returns 1 when the pass content is deterministic and can be re-generated
 * for byte-exact verification; 0 for random passes (entropy check instead). */
int  fg_pattern_deterministic(const fg_method_def *def, int pass_index);

#ifdef __cplusplus
}
#endif
#endif /* FG_ERASE_H */
