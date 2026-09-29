/* kv_carve.h - Module 3: Advanced File Carving and Recovery.
 *
 * Three recovery strategies are layered on top of each other:
 *   1. metadata recovery  - parse the filesystem and resurrect deleted entries
 *   2. structure carving  - a signature's own length fields give exact extents
 *   3. signature carving  - header..footer scan for everything else
 * plus bi-fragment gap carving for files broken in two by the allocator.
 */
#ifndef KV_CARVE_H
#define KV_CARVE_H

#include "kv_common.h"
#include "kv_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*  Signature database                                                        */
/* ========================================================================== */

typedef enum {
    KV_CAT_UNKNOWN = 0, KV_CAT_IMAGE, KV_CAT_DOCUMENT, KV_CAT_ARCHIVE,
    KV_CAT_AUDIO, KV_CAT_VIDEO, KV_CAT_EXECUTABLE, KV_CAT_DATABASE,
    KV_CAT_EMAIL, KV_CAT_FORENSIC, KV_CAT_CRYPTO, KV_CAT_DISKIMAGE, KV_CAT__COUNT
} kv_category;

const char *kv_category_name(kv_category c);

struct kv_sig;

/* A validator inspects the bytes starting at a confirmed header and decides
 * where the file really ends. Returns the exact length, or 0 if the structure
 * is not valid at all, or KV_LEN_UNKNOWN when it cannot tell (fall back to a
 * footer search). `avail` is how many bytes are readable from `p`. */
#define KV_LEN_UNKNOWN ((uint64_t)-1)
typedef uint64_t (*kv_validator_fn)(const uint8_t *p, size_t avail,
                                    const struct kv_sig *sig, int *quality);

typedef struct kv_sig {
    const char     *ext;         /* "jpg"                                     */
    const char     *desc;        /* "JPEG image"                              */
    kv_category     category;
    const uint8_t  *header;
    size_t          header_len;
    size_t          header_off;  /* header may not start at offset 0 (e.g. MP4)*/
    const uint8_t  *footer;      /* NULL if the type has no terminator        */
    size_t          footer_len;
    int             footer_inclusive;
    uint64_t        max_size;    /* carving stops here                        */
    uint64_t        min_size;
    kv_validator_fn validate;
} kv_sig;

const kv_sig *kv_sig_table(int *count);
const kv_sig *kv_sig_by_ext(const char *ext);
/* Pick the signature whose header actually matches `data`. `ext_hint` narrows
 * the search to entries with that extension (several share one). */
const kv_sig *kv_sig_match(const uint8_t *data, size_t n, const char *ext_hint);

/* ========================================================================== */
/*  Aho-Corasick multi-pattern scanner                                        */
/* ========================================================================== */

typedef struct kv_ac kv_ac;

/* Called for every header hit. `sig_index` indexes the table passed to build. */
typedef void (*kv_ac_hit_fn)(void *user, uint64_t abs_offset, int sig_index);

kv_status kv_ac_build(kv_ac **out, const kv_sig *sigs, int nsigs,
                      const int *enabled /* NULL = all */);
/* Feed a chunk. `abs_base` is the device offset of chunk[0]. Automaton state
 * carries across calls, so overlapping the chunks is not required. */
void      kv_ac_scan(kv_ac *ac, const uint8_t *chunk, size_t n,
                     uint64_t abs_base, kv_ac_hit_fn cb, void *user);
void      kv_ac_reset(kv_ac *ac);
void      kv_ac_free(kv_ac *ac);

/* ========================================================================== */
/*  Recovery results                                                          */
/* ========================================================================== */

typedef enum {
    KV_REC_METADATA = 0,  /* recovered through filesystem metadata            */
    KV_REC_STRUCTURE,     /* length taken from the file format itself         */
    KV_REC_SIGNATURE,     /* header..footer                                   */
    KV_REC_FRAGMENT,      /* reassembled from 2+ fragments                    */
    KV_REC_SLACK          /* found in file/volume slack space                 */
} kv_rec_method;

const char *kv_rec_method_name(kv_rec_method m);

typedef struct kv_recovered {
    uint32_t     index;
    char         name[512];        /* original name when known, else carved   */
    char         out_path[4096];
    const char  *ext;
    kv_category  category;
    kv_rec_method method;
    uint64_t     src_offset;       /* byte offset on the source device        */
    uint64_t     size;
    int          fragments;
    uint64_t     frag_off[8];
    uint64_t     frag_len[8];
    int          confidence;       /* 0..100                                  */
    char         confidence_why[192];
    int          header_ok;
    int          footer_ok;
    int          structure_ok;
    int          checksum_ok;      /* PNG CRC / ZIP CRC / GZIP CRC verified   */
    double       entropy;
    char         sha256[65];
    char         md5[33];
    int64_t      mtime;            /* from metadata recovery, else 0          */
    int          deleted_flag;     /* metadata said the entry was deleted     */
    int          overwritten_risk; /* 0..100, clusters likely reallocated     */
    struct kv_recovered *next;
} kv_recovered;

/* ========================================================================== */
/*  Scan options                                                              */
/* ========================================================================== */

typedef struct {
    const char *out_dir;
    const char *types;          /* "jpg,pdf,docx" or NULL for every type      */
    const char *categories;     /* "image,document" or NULL                   */
    uint64_t    start_offset;
    uint64_t    end_offset;     /* 0 = to the end of the device               */
    uint64_t    block_size;     /* read granularity, default 8 MiB            */
    uint32_t    cluster_size;   /* 0 = autodetect; used for gap carving       */
    int         do_metadata;    /* parse filesystems for deleted entries      */
    int         do_carve;       /* signature/structure carving                */
    int         do_fragment;    /* attempt bi-fragment gap carving            */
    int         do_slack;       /* scan file slack + unallocated only         */
    int         unallocated_only;
    int         min_confidence; /* discard results below this                 */
    uint64_t    max_file_size;
    int         max_results;    /* 0 = unlimited                              */
    int         write_files;    /* 0 = catalogue only, do not extract         */
    int         preserve_names;
    const char *case_id;
    const char *operator_name;
    kv_progress progress;
} kv_scan_opts;

typedef struct {
    char          source[512];
    uint64_t      source_size;
    char          source_sha256[65]; /* only when hash_source was requested   */
    uint64_t      bytes_scanned;
    uint64_t      headers_seen;
    uint64_t      files_recovered;
    uint64_t      bytes_recovered;
    uint64_t      rejected_low_confidence;
    uint64_t      fragmented_recovered;
    uint64_t      metadata_recovered;
    uint32_t      per_category[KV_CAT__COUNT];
    double        seconds;
    double        throughput_mbs;
    char          fs_detected[64];
    kv_recovered *files;
    char          started_at[32];
    char          finished_at[32];
    char          report_id[33];
    kv_status     status;
} kv_scan_result;

void      kv_scan_opts_default(kv_scan_opts *o);
kv_status kv_carve_run(const char *source_path, const kv_scan_opts *o,
                       kv_scan_result *res);
void      kv_scan_result_free(kv_scan_result *res);

/* Classification and scoring are exposed so the report layer and the tests
 * can call them directly. */
kv_category kv_classify(const uint8_t *data, size_t n, const kv_sig *sig);
int         kv_confidence_score(kv_recovered *r, const uint8_t *data, size_t n,
                                const kv_sig *sig);

#ifdef __cplusplus
}
#endif
#endif /* KV_CARVE_H */
