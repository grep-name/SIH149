/* fg_fs.h - on-disk structure parsers used by metadata-based recovery.
 * Everything here is strictly read-only: the forensic path never writes to
 * the evidence device.
 */
#ifndef FG_FS_H
#define FG_FS_H

#include "fg_common.h"
#include "fg_platform.h"
#include "fg_carve.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FG_FS_UNKNOWN = 0, FG_FS_NTFS, FG_FS_FAT12, FG_FS_FAT16, FG_FS_FAT32,
    FG_FS_EXFAT, FG_FS_EXT2, FG_FS_EXT3, FG_FS_EXT4, FG_FS_HFSPLUS,
    FG_FS_APFS, FG_FS_XFS, FG_FS_BTRFS, FG_FS_ISO9660, FG_FS_UDF
} fg_fs_kind;

const char *fg_fs_kind_name(fg_fs_kind k);

/* ---- partition tables ---------------------------------------------------- */
typedef struct {
    int        index;
    uint64_t   start_lba;
    uint64_t   sector_count;
    uint64_t   start_bytes;
    uint64_t   size_bytes;
    uint8_t    mbr_type;
    char       gpt_type[40];
    char       label[72];
    fg_fs_kind fs;
    char       fs_label[72];
    int        bootable;
} fg_partition;

#define FG_MAX_PARTS 128

typedef struct {
    int          scheme;        /* 0 = none/superfloppy, 1 = MBR, 2 = GPT     */
    int          count;
    uint32_t     sector_size;
    fg_partition parts[FG_MAX_PARTS];
} fg_partition_table;

fg_status fg_parts_read(fg_dev *d, fg_partition_table *out);

/* Identify the filesystem in the first sectors of a volume. */
fg_fs_kind fg_fs_identify(const uint8_t *boot_sector, size_t n, char *label, size_t labsz);

/* ---- metadata recovery --------------------------------------------------- */
/* Each parser walks its metadata, finds entries marked deleted, and appends
 * fg_recovered nodes. `vol_off` is the byte offset of the volume on the
 * device; `write_files` controls whether content is extracted to out_dir. */
typedef struct {
    fg_dev       *dev;
    uint64_t      vol_off;
    uint64_t      vol_size;
    const fg_scan_opts *opts;
    fg_scan_result     *res;
    uint32_t      cluster_size;
} fg_fs_ctx;

fg_status fg_ntfs_recover(fg_fs_ctx *c);
fg_status fg_fat_recover(fg_fs_ctx *c, fg_fs_kind kind);
fg_status fg_exfat_recover(fg_fs_ctx *c);
fg_status fg_ext_recover(fg_fs_ctx *c);

/* Cluster/allocation bitmap: lets the carver skip allocated areas when the
 * caller asks for unallocated-only scanning, and lets confidence scoring say
 * whether a recovered file's clusters have since been reused. */
typedef struct {
    uint8_t  *bits;        /* 1 = allocated                                   */
    uint64_t  cluster_count;
    uint32_t  cluster_size;
    uint64_t  data_start;  /* byte offset of cluster 0 on the device          */
    int       valid;
} fg_alloc_map;

fg_status fg_alloc_map_load(fg_fs_ctx *c, fg_fs_kind kind, fg_alloc_map *m);
int       fg_alloc_map_is_allocated(const fg_alloc_map *m, uint64_t byte_off);
void      fg_alloc_map_free(fg_alloc_map *m);

#ifdef __cplusplus
}
#endif
#endif /* FG_FS_H */
