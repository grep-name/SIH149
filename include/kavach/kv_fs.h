/* kv_fs.h - on-disk structure parsers used by metadata-based recovery.
 * Everything here is strictly read-only: the forensic path never writes to
 * the evidence device.
 */
#ifndef KV_FS_H
#define KV_FS_H

#include "kv_common.h"
#include "kv_platform.h"
#include "kv_carve.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    KV_FS_UNKNOWN = 0, KV_FS_NTFS, KV_FS_FAT12, KV_FS_FAT16, KV_FS_FAT32,
    KV_FS_EXFAT, KV_FS_EXT2, KV_FS_EXT3, KV_FS_EXT4, KV_FS_HFSPLUS,
    KV_FS_APFS, KV_FS_XFS, KV_FS_BTRFS, KV_FS_ISO9660, KV_FS_UDF
} kv_fs_kind;

const char *kv_fs_kind_name(kv_fs_kind k);

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
    kv_fs_kind fs;
    char       fs_label[72];
    int        bootable;
} kv_partition;

#define KV_MAX_PARTS 128

typedef struct {
    int          scheme;        /* 0 = none/superfloppy, 1 = MBR, 2 = GPT     */
    int          count;
    uint32_t     sector_size;
    kv_partition parts[KV_MAX_PARTS];
} kv_partition_table;

kv_status kv_parts_read(kv_dev *d, kv_partition_table *out);

/* Identify the filesystem in the first sectors of a volume. */
kv_fs_kind kv_fs_identify(const uint8_t *boot_sector, size_t n, char *label, size_t labsz);

/* ---- metadata recovery --------------------------------------------------- */
/* Each parser walks its metadata, finds entries marked deleted, and appends
 * kv_recovered nodes. `vol_off` is the byte offset of the volume on the
 * device; `write_files` controls whether content is extracted to out_dir. */
typedef struct {
    kv_dev       *dev;
    uint64_t      vol_off;
    uint64_t      vol_size;
    const kv_scan_opts *opts;
    kv_scan_result     *res;
    uint32_t      cluster_size;
} kv_fs_ctx;

kv_status kv_ntfs_recover(kv_fs_ctx *c);
kv_status kv_fat_recover(kv_fs_ctx *c, kv_fs_kind kind);
kv_status kv_exfat_recover(kv_fs_ctx *c);
kv_status kv_ext_recover(kv_fs_ctx *c);

/* Cluster/allocation bitmap: lets the carver skip allocated areas when the
 * caller asks for unallocated-only scanning, and lets confidence scoring say
 * whether a recovered file's clusters have since been reused. */
typedef struct {
    uint8_t  *bits;        /* 1 = allocated                                   */
    uint64_t  cluster_count;
    uint32_t  cluster_size;
    uint64_t  data_start;  /* byte offset of cluster 0 on the device          */
    int       valid;
} kv_alloc_map;

kv_status kv_alloc_map_load(kv_fs_ctx *c, kv_fs_kind kind, kv_alloc_map *m);
int       kv_alloc_map_is_allocated(const kv_alloc_map *m, uint64_t byte_off);
void      kv_alloc_map_free(kv_alloc_map *m);

#ifdef __cplusplus
}
#endif
#endif /* KV_FS_H */
