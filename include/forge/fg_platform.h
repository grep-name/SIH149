/* fg_platform.h - the only place that knows whether we are on Windows,
 * Linux or macOS. Everything above this line is portable C11.
 */
#ifndef FG_PLATFORM_H
#define FG_PLATFORM_H

#include "fg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ========================================================================== */
/*  Storage device discovery                                                  */
/* ========================================================================== */

typedef enum {
    FG_BUS_UNKNOWN = 0, FG_BUS_ATA, FG_BUS_SATA, FG_BUS_SCSI,
    FG_BUS_NVME, FG_BUS_USB, FG_BUS_SD, FG_BUS_MMC, FG_BUS_VIRTUAL, FG_BUS_RAID
} fg_bus_type;

typedef enum {
    FG_MEDIA_UNKNOWN = 0, FG_MEDIA_HDD, FG_MEDIA_SSD,
    FG_MEDIA_FLASH, FG_MEDIA_OPTICAL, FG_MEDIA_IMAGE
} fg_media_type;

typedef struct {
    char          id[64];        /* \\.\PhysicalDrive0 | /dev/sda | /dev/disk2 */
    char          model[80];
    char          serial[80];
    char          firmware[32];
    uint64_t      size_bytes;
    uint32_t      logical_sector;  /* usually 512               */
    uint32_t      physical_sector; /* 512 or 4096               */
    fg_bus_type   bus;
    fg_media_type media;
    int           removable;
    int           is_system;       /* holds a mounted OS/boot volume          */
    int           has_mounted_fs;  /* any partition currently mounted         */
    int           supports_trim;
    int           supports_ata_secure_erase;
    int           supports_nvme_sanitize;
    int           frozen;          /* ATA security state is FROZEN            */
    char          mountpoints[256];/* comma separated, best effort            */
} fg_device_info;

/* Fills up to `max` entries, returns the count found or a negative fg_status. */
int fg_dev_enumerate(fg_device_info *out, int max);

/* Populate info for one device path (also accepts a raw image file path). */
fg_status fg_dev_probe(const char *path, fg_device_info *out);

/* ---- raw device / image handle ------------------------------------------- */
typedef struct fg_dev fg_dev;

#define FG_DEV_READ   0x01
#define FG_DEV_WRITE  0x02
#define FG_DEV_DIRECT 0x04   /* bypass the OS page cache where possible */
#define FG_DEV_EXCL   0x08   /* take an exclusive lock / dismount volumes */

/* Unbuffered I/O (O_DIRECT, FILE_FLAG_NO_BUFFERING) rejects a buffer that is
 * not aligned to the device block size - malloc's 16-byte alignment is not
 * enough, and the kernel answers EINVAL rather than doing anything useful.
 * Every buffer handed to fg_dev_pread/pwrite on a FG_DEV_DIRECT handle should
 * come from here. */
#define FG_IO_ALIGN 4096
void *fg_aligned_alloc(size_t n);
void  fg_aligned_free(void *p);

fg_status fg_dev_open(const char *path, int flags, fg_dev **out);
void      fg_dev_close(fg_dev *d);
uint64_t  fg_dev_size(const fg_dev *d);
uint32_t  fg_dev_sector(const fg_dev *d);
const char *fg_dev_path(const fg_dev *d);
int       fg_dev_is_image(const fg_dev *d);

/* Positional I/O. Short reads at end-of-device are reported via *got. */
fg_status fg_dev_pread(fg_dev *d, void *buf, size_t n, uint64_t off, size_t *got);
fg_status fg_dev_pwrite(fg_dev *d, const void *buf, size_t n, uint64_t off, size_t *put);
fg_status fg_dev_flush(fg_dev *d);

/* Firmware-level sanitize. Returns FG_ERR_UNSUPPORTED when the platform or
 * the device cannot do it; callers then fall back to overwriting. */
typedef enum {
    FG_FW_ATA_SECURE_ERASE,
    FG_FW_ATA_SECURE_ERASE_ENHANCED,
    FG_FW_ATA_SANITIZE_BLOCK,
    FG_FW_ATA_SANITIZE_CRYPTO,
    FG_FW_NVME_FORMAT_USER,
    FG_FW_NVME_FORMAT_CRYPTO,
    FG_FW_NVME_SANITIZE_BLOCK,
    FG_FW_NVME_SANITIZE_CRYPTO,
    FG_FW_TRIM_DISCARD
} fg_fw_op;

fg_status fg_dev_firmware_sanitize(fg_dev *d, fg_fw_op op, char *msg, size_t msgsz);

/* Unmount/dismount every volume on the device so writes are not fought over. */
fg_status fg_dev_dismount_volumes(const char *device_id);

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
} fg_fs_entry;

fg_status fg_fs_stat(const char *path, fg_fs_entry *out);
int       fg_fs_exists(const char *path);
fg_status fg_fs_mkdirs(const char *path);
fg_status fg_fs_remove(const char *path);       /* file  */
fg_status fg_fs_rmdir(const char *path);        /* empty dir */
fg_status fg_fs_rename(const char *from, const char *to);
fg_status fg_fs_truncate(const char *path, uint64_t len);
fg_status fg_fs_set_times(const char *path, int64_t atime, int64_t mtime);
fg_status fg_fs_clear_attrs(const char *path);  /* readonly/hidden/system     */
fg_status fg_fs_free_space(const char *path, uint64_t *free_bytes,
                           uint64_t *total_bytes, uint32_t *cluster_size);
fg_status fg_fs_type(const char *path, char *out, size_t outsz); /* "NTFS"... */

/* Directory walk. cb returns non-zero to stop the walk early. */
typedef int (*fg_walk_fn)(void *user, const fg_fs_entry *e);
fg_status fg_fs_walk(const char *root, int recursive, fg_walk_fn cb, void *user);

/* Metadata residue: NTFS alternate data streams, POSIX extended attributes,
 * macOS resource forks. Each returns how many were removed. */
int fg_fs_wipe_alt_streams(const char *path);
int fg_fs_wipe_xattrs(const char *path);

/* Open a file for in-place overwriting with caching disabled where possible. */
typedef struct fg_file fg_file;
fg_status fg_file_open_rw(const char *path, int direct, fg_file **out);
fg_status fg_file_write_at(fg_file *f, const void *buf, size_t n, uint64_t off, size_t *put);
fg_status fg_file_read_at(fg_file *f, void *buf, size_t n, uint64_t off, size_t *got);
fg_status fg_file_sync(fg_file *f);
uint64_t  fg_file_size(fg_file *f);
void      fg_file_close(fg_file *f);

/* ========================================================================== */
/*  Process / environment                                                     */
/* ========================================================================== */

int  fg_is_elevated(void);                 /* Administrator or uid 0          */
void fg_os_describe(char *out, size_t n);  /* "Windows 11 (build 22631) x64"  */
void fg_hostname(char *out, size_t n);
void fg_username(char *out, size_t n);
fg_status fg_temp_dir(char *out, size_t n);

/* ========================================================================== */
/*  Threads (minimal - just what the job manager needs)                       */
/* ========================================================================== */

typedef struct fg_thread fg_thread;
typedef struct fg_mutex  fg_mutex;

fg_status fg_thread_start(fg_thread **out, void (*fn)(void *), void *arg);
void      fg_thread_join(fg_thread *t);
void      fg_thread_detach(fg_thread *t);
void      fg_sleep_ms(unsigned ms);

fg_status fg_mutex_create(fg_mutex **out);
void      fg_mutex_lock(fg_mutex *m);
void      fg_mutex_unlock(fg_mutex *m);
void      fg_mutex_destroy(fg_mutex *m);

/* ========================================================================== */
/*  Sockets (for the embedded dashboard server)                               */
/* ========================================================================== */

typedef intptr_t fg_socket;
#define FG_INVALID_SOCKET ((fg_socket)-1)

fg_status  fg_net_startup(void);
void       fg_net_cleanup(void);
fg_socket  fg_net_listen(const char *bind_addr, int port);
fg_socket  fg_net_accept(fg_socket srv, char *peer, size_t peersz);
int        fg_net_recv(fg_socket s, void *buf, int n);
int        fg_net_send(fg_socket s, const void *buf, int n);
void       fg_net_close(fg_socket s);
void       fg_net_set_timeout(fg_socket s, int seconds);

#ifdef __cplusplus
}
#endif
#endif /* FG_PLATFORM_H */
