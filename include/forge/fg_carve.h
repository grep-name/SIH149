/* fg_carve.h - Module 3: Advanced File Carving and Recovery.
 *
 * Three recovery strategies are layered on top of each other:
 *   1. metadata recovery  - parse the filesystem and resurrect deleted entries
 *   2. structure carving  - a signature's own length fields give exact extents
 *   3. signature carving  - header..footer scan for everything else
 * plus bi-fragment gap carving for files broken in two by the allocator.
 */
#ifndef FG_CARVE_H
#define FG_CARVE_H

#include "fg_common.h"
#include "fg_platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*  Signature database                                                        */
/* ========================================================================== */

typedef enum {
    FG_CAT_UNKNOWN = 0, FG_CAT_IMAGE, FG_CAT_DOCUMENT, FG_CAT_ARCHIVE,
    FG_CAT_AUDIO, FG_CAT_VIDEO, FG_CAT_EXECUTABLE, FG_CAT_DATABASE,
    FG_CAT_EMAIL, FG_CAT_FORENSIC, FG_CAT_CRYPTO, FG_CAT_DISKIMAGE, FG_CAT__COUNT
} fg_category;

const char *fg_category_name(fg_category c);

struct fg_sig;

/* A validator inspects the bytes starting at a confirmed header and decides
 * where the file really ends. Returns the exact length, or 0 if the structure
 * is not valid at all, or FG_LEN_UNKNOWN when it cannot tell (fall back to a
 * footer search). `avail` is how many bytes are readable from `p`. */
#define FG_LEN_UNKNOWN ((uint64_t)-1)
typedef uint64_t (*fg_validator_fn)(const uint8_t *p, size_t avail,
                                    const struct fg_sig *sig, int *quality);

typedef struct fg_sig {
    const char     *ext;         /* "jpg"                                     */
    const char     *desc;        /* "JPEG image"                              */
    fg_category     category;
    const uint8_t  *header;
    size_t          header_len;
    size_t          header_off;  /* header may not start at offset 0 (e.g. MP4)*/
    const uint8_t  *footer;      /* NULL if the type has no terminator        */
    size_t          footer_len;
    int             footer_inclusive;
    uint64_t        max_size;    /* carving stops here                        */
    uint64_t        min_size;
    fg_validator_fn validate;
} fg_sig;

const fg_sig *fg_sig_table(int *count);
const fg_sig *fg_sig_by_ext(const char *ext);
/* Pick the signature whose header actually matches `data`. `ext_hint` narrows
 * the search to entries with that extension (several share one). */
const fg_sig *fg_sig_match(const uint8_t *data, size_t n, const char *ext_hint);

/* ========================================================================== */
/*  Aho-Corasick multi-pattern scanner                                        */
/* ========================================================================== */

typedef struct fg_ac fg_ac;

/* Called for every header hit. `sig_index` indexes the table passed to build. */
typedef void (*fg_ac_hit_fn)(void *user, uint64_t abs_offset, int sig_index);

fg_status fg_ac_build(fg_ac **out, const fg_sig *sigs, int nsigs,
                      const int *enabled /* NULL = all */);
/* Feed a chunk. `abs_base` is the device offset of chunk[0]. Automaton state
 * carries across calls, so overlapping the chunks is not required. */
void      fg_ac_scan(fg_ac *ac, const uint8_t *chunk, size_t n,
                     uint64_t abs_base, fg_ac_hit_fn cb, void *user);
void      fg_ac_reset(fg_ac *ac);
void      fg_ac_free(fg_ac *ac);

/* ========================================================================== */
/*  Recovery results                                                          */
/* ========================================================================== */

typedef enum {
    FG_REC_METADATA = 0,  /* recovered through filesystem metadata            */
    FG_REC_STRUCTURE,     /* length taken from the file format itself         */
    FG_REC_SIGNATURE,     /* header..footer                                   */
    FG_REC_FRAGMENT,      /* reassembled from 2+ fragments                    */
    FG_REC_SLACK          /* found in file/volume slack space                 */
} fg_rec_method;

const char *fg_rec_method_name(fg_rec_method m);

typedef struct fg_recovered {
    uint32_t     index;
    char         name[512];        /* original name when known, else carved   */
    char         out_path[4096];
    const char  *ext;
    fg_category  category;
    fg_rec_method method;
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
    struct fg_recovered *next;
} fg_recovered;

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
    fg_progress progress;
} fg_scan_opts;

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
    uint32_t      per_category[FG_CAT__COUNT];
    double        seconds;
    double        throughput_mbs;
    char          fs_detected[64];
    fg_recovered *files;
    char          started_at[32];
    char          finished_at[32];
    char          report_id[33];
    fg_status     status;
} fg_scan_result;

void      fg_scan_opts_default(fg_scan_opts *o);
fg_status fg_carve_run(const char *source_path, const fg_scan_opts *o,
                       fg_scan_result *res);
void      fg_scan_result_free(fg_scan_result *res);

/* Classification and scoring are exposed so the report layer and the tests
 * can call them directly. */
fg_category fg_classify(const uint8_t *data, size_t n, const fg_sig *sig);
int         fg_confidence_score(fg_recovered *r, const uint8_t *data, size_t n,
                                const fg_sig *sig);

#ifdef __cplusplus
}
#endif
#endif /* FG_CARVE_H */
