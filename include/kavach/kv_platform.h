/* kv_platform.h - the only place that knows whether we are on Windows,
 * Linux or macOS. Everything above this line is portable C11.
 */
#ifndef KV_PLATFORM_H
#define KV_PLATFORM_H

#include "kv_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*  Storage device discovery                                                  */
/* ========================================================================== */

typedef enum {
    KV_BUS_UNKNOWN = 0, KV_BUS_ATA, KV_BUS_SATA, KV_BUS_SCSI,
    KV_BUS_NVME, KV_BUS_USB, KV_BUS_SD, KV_BUS_MMC, KV_BUS_VIRTUAL, KV_BUS_RAID
} kv_bus_type;

typedef enum {
    KV_MEDIA_UNKNOWN = 0, KV_MEDIA_HDD, KV_MEDIA_SSD,
    KV_MEDIA_FLASH, KV_MEDIA_OPTICAL, KV_MEDIA_IMAGE
} kv_media_type;

typedef struct {
    char          id[64];        /* \\.\PhysicalDrive0 | /dev/sda | /dev/disk2 */
    char          model[80];
    char          serial[80];
    char          firmware[32];
    uint64_t      size_bytes;
    uint32_t      logical_sector;  /* usually 512               */
    uint32_t      physical_sector; /* 512 or 4096               */
    kv_bus_type   bus;
    kv_media_type media;
    int           removable;
    int           is_system;       /* holds a mounted OS/boot volume          */
    int           has_mounted_fs;  /* any partition currently mounted         */
    int           supports_trim;
    int           supports_ata_secure_erase;
    int           supports_nvme_sanitize;
    int           frozen;          /* ATA security state is FROZEN            */
    char          mountpoints[256];/* comma separated, best effort            */
} kv_device_info;

/* Fills up to `max` entries, returns the count found or a negative kv_status. */
int kv_dev_enumerate(kv_device_info *out, int max);

/* Populate info for one device path (also accepts a raw image file path). */
kv_status kv_dev_probe(const char *path, kv_device_info *out);

/* ---- raw device / image handle ------------------------------------------- */
typedef struct kv_dev kv_dev;

#define KV_DEV_READ   0x01
#define KV_DEV_WRITE  0x02
#define KV_DEV_DIRECT 0x04   /* bypass the OS page cache where possible */
#define KV_DEV_EXCL   0x08   /* take an exclusive lock / dismount volumes */

/* Unbuffered I/O (O_DIRECT, FILE_FLAG_NO_BUFFERING) rejects a buffer that is
 * not aligned to the device block size - malloc's 16-byte alignment is not
 * enough, and the kernel answers EINVAL rather than doing anything useful.
 * Every buffer handed to kv_dev_pread/pwrite on a KV_DEV_DIRECT handle should
 * come from here. */
#define KV_IO_ALIGN 4096
void *kv_aligned_alloc(size_t n);
void  kv_aligned_free(void *p);

kv_status kv_dev_open(const char *path, int flags, kv_dev **out);
void      kv_dev_close(kv_dev *d);
uint64_t  kv_dev_size(const kv_dev *d);
uint32_t  kv_dev_sector(const kv_dev *d);
const char *kv_dev_path(const kv_dev *d);
int       kv_dev_is_image(const kv_dev *d);

/* Positional I/O. Short reads at end-of-device are reported via *got. */
kv_status kv_dev_pread(kv_dev *d, void *buf, size_t n, uint64_t off, size_t *got);
kv_status kv_dev_pwrite(kv_dev *d, const void *buf, size_t n, uint64_t off, size_t *put);
kv_status kv_dev_flush(kv_dev *d);

/* Firmware-level sanitize. Returns KV_ERR_UNSUPPORTED when the platform or
 * the device cannot do it; callers then fall back to overwriting. */
typedef enum {
    KV_FW_ATA_SECURE_ERASE,
    KV_FW_ATA_SECURE_ERASE_ENHANCED,
    KV_FW_ATA_SANITIZE_BLOCK,
    KV_FW_ATA_SANITIZE_CRYPTO,
    KV_FW_NVME_FORMAT_USER,
    KV_FW_NVME_FORMAT_CRYPTO,
    KV_FW_NVME_SANITIZE_BLOCK,
    KV_FW_NVME_SANITIZE_CRYPTO,
    KV_FW_TRIM_DISCARD
} kv_fw_op;

kv_status kv_dev_firmware_sanitize(kv_dev *d, kv_fw_op op, char *msg, size_t msgsz);

/* Unmount/dismount every volume on the device so writes are not fought over. */
kv_status kv_dev_dismount_volumes(const char *device_id);

/* ========================================================================== */
/*  Filesystem services                                                       */
/* ========================================================================== */

typedef struct {
    char     path[4096];
    char     name[512];
    uint64_t size;
    int64_t  mtime;       /* unix seconds */
    int64_t  atime;
    int64_t  ctime;
    int      is_dir;
    int      is_symlink;
    int      is_sparse;
    int      is_readonly;
    int      is_compressed;
    int      is_encrypted;
} kv_fs_entry;

kv_status kv_fs_stat(const char *path, kv_fs_entry *out);
int       kv_fs_exists(const char *path);
kv_status kv_fs_mkdirs(const char *path);
kv_status kv_fs_remove(const char *path);       /* file  */
kv_status kv_fs_rmdir(const char *path);        /* empty dir */
kv_status kv_fs_rename(const char *from, const char *to);
kv_status kv_fs_truncate(const char *path, uint64_t len);
kv_status kv_fs_set_times(const char *path, int64_t atime, int64_t mtime);
kv_status kv_fs_clear_attrs(const char *path);  /* readonly/hidden/system     */
kv_status kv_fs_free_space(const char *path, uint64_t *free_bytes,
                           uint64_t *total_bytes, uint32_t *cluster_size);
kv_status kv_fs_type(const char *path, char *out, size_t outsz); /* "NTFS"... */

/* Directory walk. cb returns non-zero to stop the walk early. */
typedef int (*kv_walk_fn)(void *user, const kv_fs_entry *e);
kv_status kv_fs_walk(const char *root, int recursive, kv_walk_fn cb, void *user);

/* Metadata residue: NTFS alternate data streams, POSIX extended attributes,
 * macOS resource forks. Each returns how many were removed. */
int kv_fs_wipe_alt_streams(const char *path);
int kv_fs_wipe_xattrs(const char *path);

/* Open a file for in-place overwriting with caching disabled where possible. */
typedef struct kv_file kv_file;
kv_status kv_file_open_rw(const char *path, int direct, kv_file **out);
kv_status kv_file_write_at(kv_file *f, const void *buf, size_t n, uint64_t off, size_t *put);
kv_status kv_file_read_at(kv_file *f, void *buf, size_t n, uint64_t off, size_t *got);
kv_status kv_file_sync(kv_file *f);
uint64_t  kv_file_size(kv_file *f);
void      kv_file_close(kv_file *f);

/* ========================================================================== */
/*  Process / environment                                                     */
/* ========================================================================== */

int  kv_is_elevated(void);                 /* Administrator or uid 0          */
void kv_os_describe(char *out, size_t n);  /* "Windows 11 (build 22631) x64"  */
void kv_hostname(char *out, size_t n);
void kv_username(char *out, size_t n);
kv_status kv_temp_dir(char *out, size_t n);

/* ========================================================================== */
/*  Threads (minimal - just what the job manager needs)                       */
/* ========================================================================== */

typedef struct kv_thread kv_thread;
typedef struct kv_mutex  kv_mutex;

kv_status kv_thread_start(kv_thread **out, void (*fn)(void *), void *arg);
void      kv_thread_join(kv_thread *t);
void      kv_thread_detach(kv_thread *t);
void      kv_sleep_ms(unsigned ms);

kv_status kv_mutex_create(kv_mutex **out);
void      kv_mutex_lock(kv_mutex *m);
void      kv_mutex_unlock(kv_mutex *m);
void      kv_mutex_destroy(kv_mutex *m);

/* ========================================================================== */
/*  Sockets (for the embedded dashboard server)                               */
/* ========================================================================== */

typedef intptr_t kv_socket;
#define KV_INVALID_SOCKET ((kv_socket)-1)

kv_status  kv_net_startup(void);
void       kv_net_cleanup(void);
kv_socket  kv_net_listen(const char *bind_addr, int port);
kv_socket  kv_net_accept(kv_socket srv, char *peer, size_t peersz);
int        kv_net_recv(kv_socket s, void *buf, int n);
int        kv_net_send(kv_socket s, const void *buf, int n);
void       kv_net_close(kv_socket s);
void       kv_net_set_timeout(kv_socket s, int seconds);

#ifdef __cplusplus
}
#endif
#endif /* KV_PLATFORM_H */
