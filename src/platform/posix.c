/* posix.c - Linux and macOS implementation of fg_platform.h */
#include "forge/fg_platform.h"

#if !FG_WINDOWS

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <time.h>
#include <utime.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <pwd.h>

#if FG_LINUX
#  include <linux/fs.h>
#  include <sys/xattr.h>
#  include <scsi/sg.h>
#  include <sys/mount.h>
#  ifndef BLKDISCARD
#    define BLKDISCARD _IO(0x12, 119)
#  endif
#  ifndef BLKSECDISCARD
#    define BLKSECDISCARD _IO(0x12, 125)
#  endif
#  ifndef BLKGETSIZE64
#    define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#  endif
#  ifndef BLKSSZGET
#    define BLKSSZGET _IO(0x12, 104)
#  endif
#  ifndef BLKPBSZGET
#    define BLKPBSZGET _IO(0x12, 123)
#  endif
#endif

#if FG_MACOS
#  include <sys/disk.h>
#  include <sys/xattr.h>
#  include <sys/param.h>
#  include <sys/mount.h>
#endif

/* ========================================================================== */
/*  aligned I/O buffers                                                       */
/* ========================================================================== */
void *fg_aligned_alloc(size_t n)
{
    void *p = NULL;
    size_t rounded = (n + FG_IO_ALIGN - 1) & ~(size_t)(FG_IO_ALIGN - 1);
    if (posix_memalign(&p, FG_IO_ALIGN, rounded) != 0) return NULL;
    return p;
}

void fg_aligned_free(void *p) { free(p); }

/* ========================================================================== */
/*  device handle                                                             */
/* ========================================================================== */
struct fg_dev {
    int      fd;
    char     path[512];
    uint64_t size;
    uint32_t sector;
    int      is_image;
    int      writable;
    int      direct;      /* O_DIRECT is active: alignment rules apply */
};

static uint64_t fd_block_size(int fd, uint32_t *sector)
{
    uint64_t sz = 0;
    if (sector) *sector = 512;
#if FG_LINUX
    {
        unsigned long long b = 0;
        int ss = 0;
        if (ioctl(fd, BLKGETSIZE64, &b) == 0) sz = b;
        if (sector && ioctl(fd, BLKSSZGET, &ss) == 0 && ss > 0) *sector = (uint32_t)ss;
    }
#elif FG_MACOS
    {
        uint32_t bs = 0;
        uint64_t bc = 0;
        if (ioctl(fd, DKIOCGETBLOCKSIZE, &bs) == 0 &&
            ioctl(fd, DKIOCGETBLOCKCOUNT, &bc) == 0) {
            sz = bs * bc;
            if (sector) *sector = bs;
        }
    }
#endif
    if (!sz) {
        off_t e = lseek(fd, 0, SEEK_END);
        if (e > 0) sz = (uint64_t)e;
        lseek(fd, 0, SEEK_SET);
    }
    return sz;
}

fg_status fg_dev_open(const char *path, int flags, fg_dev **out)
{
    fg_dev *d;
    int oflags = 0;
    struct stat st;

    if (!path || !out) return FG_ERR_INVALID;
    *out = NULL;

    if ((flags & FG_DEV_WRITE) && (flags & FG_DEV_READ)) oflags = O_RDWR;
    else if (flags & FG_DEV_WRITE)                        oflags = O_WRONLY;
    else                                                  oflags = O_RDONLY;
#if FG_LINUX
    if (flags & FG_DEV_DIRECT) oflags |= O_DIRECT;
    if (flags & FG_DEV_EXCL)   oflags |= O_EXCL;
#endif

    d = (fg_dev *)fg_xcalloc(1, sizeof *d);
    if (!d) return FG_ERR_NOMEM;

    d->fd = open(path, oflags);
#if FG_LINUX
    if (d->fd < 0 && (oflags & O_DIRECT)) {   /* filesystems may refuse O_DIRECT */
        oflags &= ~O_DIRECT;
        d->fd = open(path, oflags);
    }
    if (d->fd < 0 && (oflags & O_EXCL)) {
        oflags &= ~O_EXCL;
        d->fd = open(path, oflags);
    }
#endif
    if (d->fd < 0) {
        fg_status st2 = (errno == EACCES || errno == EPERM) ? FG_ERR_PERM
                      : (errno == ENOENT) ? FG_ERR_NOTFOUND
                      : (errno == EBUSY)  ? FG_ERR_BUSY : FG_ERR_IO;
        free(d);
        return st2;
    }

    snprintf(d->path, sizeof d->path, "%s", path);
    d->writable = (flags & FG_DEV_WRITE) ? 1 : 0;
#if FG_LINUX
    d->direct = (oflags & O_DIRECT) ? 1 : 0;
#endif
    if (fstat(d->fd, &st) == 0) d->is_image = S_ISREG(st.st_mode);
    d->size = fd_block_size(d->fd, &d->sector);
    if (d->is_image) d->sector = 512;
#if FG_MACOS
    if (flags & FG_DEV_DIRECT) fcntl(d->fd, F_NOCACHE, 1);
#endif
    *out = d;
    return FG_OK;
}

void fg_dev_close(fg_dev *d)
{
    if (!d) return;
    if (d->writable) fsync(d->fd);
    close(d->fd);
    free(d);
}

uint64_t    fg_dev_size(const fg_dev *d)     { return d ? d->size : 0; }
uint32_t    fg_dev_sector(const fg_dev *d)   { return d ? d->sector : 512; }
const char *fg_dev_path(const fg_dev *d)     { return d ? d->path : ""; }
int         fg_dev_is_image(const fg_dev *d) { return d ? d->is_image : 0; }

/* ---- positional I/O ------------------------------------------------------ *
 * Unbuffered I/O imposes three alignment rules: the buffer address, the
 * length and the offset must all be multiples of the device block size (the
 * buffer, in practice, of the page size). A request that breaks any of them
 * fails with EINVAL - which, on a sanitization run, would look exactly like a
 * drive full of bad sectors. Callers on the hot paths allocate with
 * fg_aligned_alloc; everything else is bounced through an aligned scratch
 * buffer here so the API is simply always correct.
 */
static int needs_bounce(const fg_dev *d, const void *buf, size_t n, uint64_t off)
{
    uint32_t a = d->sector ? d->sector : 512;
    if (!d->direct) return 0;
    return ((uintptr_t)buf % FG_IO_ALIGN) != 0 || (n % a) != 0 || (off % a) != 0;
}

static fg_status pread_raw(fg_dev *d, void *buf, size_t n, uint64_t off, size_t *got)
{
    uint8_t *p = (uint8_t *)buf;
    size_t left = n, total = 0;
    if (got) *got = 0;
    while (left) {
        ssize_t r = pread(d->fd, p, left, (off_t)(off + total));
        if (r < 0) {
            if (errno == EINTR) continue;
            if (got) *got = total;
            return total ? FG_OK : FG_ERR_IO;
        }
        if (r == 0) break;                    /* end of device */
        p += r; left -= (size_t)r; total += (size_t)r;
    }
    if (got) *got = total;
    return total ? FG_OK : FG_ERR_IO;
}

static fg_status pwrite_raw(fg_dev *d, const void *buf, size_t n, uint64_t off, size_t *put)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = n, total = 0;
    if (put) *put = 0;
    while (left) {
        ssize_t r = pwrite(d->fd, p, left, (off_t)(off + total));
        if (r < 0) {
            if (errno == EINTR) continue;
            if (put) *put = total;
            return (errno == ENOSPC) ? FG_ERR_RANGE : FG_ERR_IO;
        }
        if (r == 0) break;
        p += r; left -= (size_t)r; total += (size_t)r;
    }
    if (put) *put = total;
    return (total == n) ? FG_OK : FG_ERR_IO;
}

fg_status fg_dev_pread(fg_dev *d, void *buf, size_t n, uint64_t off, size_t *got)
{
    if (!needs_bounce(d, buf, n, off)) return pread_raw(d, buf, n, off, got);
    {
        uint32_t a = d->sector ? d->sector : 512;
        uint64_t lo = off - (off % a);
        uint64_t hi = (off + n + a - 1) / a * a;
        size_t span = (size_t)(hi - lo), inner = 0, skip = (size_t)(off - lo);
        uint8_t *tmp = (uint8_t *)fg_aligned_alloc(span);
        fg_status st;
        if (got) *got = 0;
        if (!tmp) return FG_ERR_NOMEM;
        st = pread_raw(d, tmp, span, lo, &inner);
        if (st == FG_OK && inner > skip) {
            size_t take = FG_MIN(inner - skip, n);
            memcpy(buf, tmp + skip, take);
            if (got) *got = take;
        }
        fg_aligned_free(tmp);
        return st;
    }
}

fg_status fg_dev_pwrite(fg_dev *d, const void *buf, size_t n, uint64_t off, size_t *put)
{
    if (!needs_bounce(d, buf, n, off)) return pwrite_raw(d, buf, n, off, put);
    {
        /* Read-modify-write the surrounding aligned window. Only the tail of a
         * device whose size is not a whole number of blocks ever lands here. */
        uint32_t a = d->sector ? d->sector : 512;
        uint64_t lo = off - (off % a);
        uint64_t hi = (off + n + a - 1) / a * a;
        size_t span = (size_t)(hi - lo), skip = (size_t)(off - lo), done = 0;
        uint8_t *tmp = (uint8_t *)fg_aligned_alloc(span);
        fg_status st;
        if (put) *put = 0;
        if (!tmp) return FG_ERR_NOMEM;
        memset(tmp, 0, span);
        pread_raw(d, tmp, span, lo, &done);
        memcpy(tmp + skip, buf, n);
        st = pwrite_raw(d, tmp, span, lo, &done);
        if (st == FG_OK && put) *put = n;
        fg_aligned_free(tmp);
        return st;
    }
}

fg_status fg_dev_flush(fg_dev *d)
{
#if FG_MACOS
    if (fcntl(d->fd, F_FULLFSYNC, 0) == 0) return FG_OK;
#endif
    return fsync(d->fd) == 0 ? FG_OK : FG_ERR_IO;
}

/* ---- firmware sanitize --------------------------------------------------- */
#if FG_LINUX
/* ATA pass-through via SG_IO / ATA-16, used for SECURITY ERASE UNIT and the
 * ATA SANITIZE feature set. Requires CAP_SYS_RAWIO. */
static int ata16(int fd, const uint8_t cdb_in[16], unsigned timeout_s, char *msg, size_t msgsz)
{
    sg_io_hdr_t io;
    uint8_t sense[32], cdb[16];
    memcpy(cdb, cdb_in, 16);
    memset(&io, 0, sizeof io);
    memset(sense, 0, sizeof sense);
    io.interface_id    = 'S';
    io.cmd_len         = 16;
    io.cmdp            = cdb;
    io.dxfer_direction = SG_DXFER_NONE;
    io.sbp             = sense;
    io.mx_sb_len       = sizeof sense;
    io.timeout         = timeout_s * 1000u;
    if (ioctl(fd, SG_IO, &io) < 0) {
        snprintf(msg, msgsz, "SG_IO failed: %s", strerror(errno));
        return -1;
    }
    if (io.status != 0 && io.status != 2 /* CHECK CONDITION carries ATA result */) {
        snprintf(msg, msgsz, "ATA command status 0x%02x", io.status);
        return -1;
    }
    return 0;
}

static int ata_security_erase(int fd, int enhanced, char *msg, size_t msgsz)
{
    /* SECURITY SET PASSWORD then SECURITY ERASE PREPARE then ERASE UNIT.
     * The password data-out phase needs a 512-byte buffer, so build it. */
    uint8_t buf[512], cdb[16];
    sg_io_hdr_t io;
    uint8_t sense[32];
    static const char pw[] = "ForgeTempPW";

    memset(buf, 0, sizeof buf);
    buf[0] = 0x00; buf[1] = 0x00;               /* master/user + high security */
    memcpy(buf + 2, pw, sizeof pw - 1);

    /* 1. SECURITY SET PASSWORD (0xF1), PIO data-out, 1 sector */
    memset(cdb, 0, sizeof cdb);
    cdb[0] = 0x85;          /* ATA PASS-THROUGH (16)                          */
    cdb[1] = (3 << 1) | 0;  /* protocol 3 = PIO Data-Out                      */
    cdb[2] = 0x06;          /* T_LENGTH=2 (sector count), T_DIR=0 (out)       */
    cdb[6] = 0x01;          /* sector count = 1                               */
    cdb[14] = 0xF1;
    memset(&io, 0, sizeof io);
    memset(sense, 0, sizeof sense);
    io.interface_id = 'S'; io.cmd_len = 16; io.cmdp = cdb;
    io.dxfer_direction = SG_DXFER_TO_DEV;
    io.dxferp = buf; io.dxfer_len = 512;
    io.sbp = sense; io.mx_sb_len = sizeof sense; io.timeout = 15000;
    if (ioctl(fd, SG_IO, &io) < 0) {
        snprintf(msg, msgsz, "SECURITY SET PASSWORD rejected: %s", strerror(errno));
        return -1;
    }

    /* 2. SECURITY ERASE PREPARE (0xF3), non-data */
    memset(cdb, 0, sizeof cdb);
    cdb[0] = 0x85; cdb[1] = (3 << 1); cdb[2] = 0x20; cdb[14] = 0xF3;
    if (ata16(fd, cdb, 15, msg, msgsz) < 0) return -1;

    /* 3. SECURITY ERASE UNIT (0xF4), PIO data-out with the same password.
     *    Drives take minutes to hours; allow a long timeout. */
    memset(buf, 0, sizeof buf);
    buf[0] = enhanced ? 0x02 : 0x00;
    memcpy(buf + 2, pw, sizeof pw - 1);
    memset(cdb, 0, sizeof cdb);
    cdb[0] = 0x85; cdb[1] = (3 << 1); cdb[2] = 0x06; cdb[6] = 0x01; cdb[14] = 0xF4;
    memset(&io, 0, sizeof io);
    memset(sense, 0, sizeof sense);
    io.interface_id = 'S'; io.cmd_len = 16; io.cmdp = cdb;
    io.dxfer_direction = SG_DXFER_TO_DEV;
    io.dxferp = buf; io.dxfer_len = 512;
    io.sbp = sense; io.mx_sb_len = sizeof sense;
    io.timeout = 12u * 3600u * 1000u;
    if (ioctl(fd, SG_IO, &io) < 0) {
        snprintf(msg, msgsz, "SECURITY ERASE UNIT failed: %s", strerror(errno));
        return -1;
    }
    snprintf(msg, msgsz, "ATA SECURITY ERASE UNIT (%s) completed",
             enhanced ? "enhanced" : "normal");
    return 0;
}

static int ata_sanitize(int fd, int crypto, char *msg, size_t msgsz)
{
    uint8_t cdb[16];
    memset(cdb, 0, sizeof cdb);
    cdb[0] = 0x85;
    cdb[1] = (3 << 1);
    cdb[2] = 0x20;                     /* non-data, check condition           */
    cdb[4] = crypto ? 0x11 : 0x12;     /* feature: CRYPTO_SCRAMBLE / BLOCK_ERASE */
    cdb[10] = 0x43; cdb[12] = 0x4B;    /* required key 0x4372, 0x4B*/
    cdb[8]  = 0x72;
    cdb[14] = 0xB4;                    /* SANITIZE DEVICE                     */
    if (ata16(fd, cdb, 60, msg, msgsz) < 0) return -1;
    snprintf(msg, msgsz, "ATA SANITIZE %s issued",
             crypto ? "CRYPTO SCRAMBLE" : "BLOCK ERASE");
    return 0;
}

/* NVMe Format NVM with a Secure Erase Setting. */
struct fg_nvme_passthru {
    uint8_t  opcode, flags; uint16_t rsvd1; uint32_t nsid;
    uint32_t cdw2, cdw3; uint64_t metadata; uint64_t addr;
    uint32_t metadata_len, data_len;
    uint32_t cdw10, cdw11, cdw12, cdw13, cdw14, cdw15;
    uint32_t timeout_ms, result;
};
#define FG_NVME_IOCTL_ADMIN_CMD _IOWR('N', 0x41, struct fg_nvme_passthru)

static int nvme_admin(int fd, struct fg_nvme_passthru *c, char *msg, size_t msgsz)
{
    int r = ioctl(fd, FG_NVME_IOCTL_ADMIN_CMD, c);
    if (r < 0) { snprintf(msg, msgsz, "NVMe admin ioctl: %s", strerror(errno)); return -1; }
    if (r > 0) { snprintf(msg, msgsz, "NVMe controller returned status 0x%x", r); return -1; }
    return 0;
}
#endif /* FG_LINUX */

fg_status fg_dev_firmware_sanitize(fg_dev *d, fg_fw_op op, char *msg, size_t msgsz)
{
    if (msg && msgsz) msg[0] = '\0';
    if (!d) return FG_ERR_INVALID;
    if (d->is_image) {
        snprintf(msg, msgsz, "source is a disk image; firmware commands do not apply");
        return FG_ERR_UNSUPPORTED;
    }
#if FG_LINUX
    switch (op) {
    case FG_FW_ATA_SECURE_ERASE:
        return ata_security_erase(d->fd, 0, msg, msgsz) == 0 ? FG_OK : FG_ERR_UNSUPPORTED;
    case FG_FW_ATA_SECURE_ERASE_ENHANCED:
        return ata_security_erase(d->fd, 1, msg, msgsz) == 0 ? FG_OK : FG_ERR_UNSUPPORTED;
    case FG_FW_ATA_SANITIZE_BLOCK:
        return ata_sanitize(d->fd, 0, msg, msgsz) == 0 ? FG_OK : FG_ERR_UNSUPPORTED;
    case FG_FW_ATA_SANITIZE_CRYPTO:
        return ata_sanitize(d->fd, 1, msg, msgsz) == 0 ? FG_OK : FG_ERR_UNSUPPORTED;
    case FG_FW_NVME_FORMAT_USER:
    case FG_FW_NVME_FORMAT_CRYPTO: {
        struct fg_nvme_passthru c;
        memset(&c, 0, sizeof c);
        c.opcode = 0x80;                 /* Format NVM                        */
        c.nsid   = 0xFFFFFFFFu;
        c.cdw10  = (uint32_t)((op == FG_FW_NVME_FORMAT_CRYPTO ? 2u : 1u) << 9);
        c.timeout_ms = 10u * 60u * 1000u;
        if (nvme_admin(d->fd, &c, msg, msgsz) < 0) return FG_ERR_UNSUPPORTED;
        snprintf(msg, msgsz, "NVMe Format NVM (SES=%s) completed",
                 op == FG_FW_NVME_FORMAT_CRYPTO ? "crypto erase" : "user data erase");
        return FG_OK;
    }
    case FG_FW_NVME_SANITIZE_BLOCK:
    case FG_FW_NVME_SANITIZE_CRYPTO: {
        struct fg_nvme_passthru c;
        memset(&c, 0, sizeof c);
        c.opcode = 0x84;                 /* Sanitize                          */
        c.nsid   = 0xFFFFFFFFu;
        c.cdw10  = (op == FG_FW_NVME_SANITIZE_CRYPTO) ? 4u : 2u;  /* SANACT   */
        c.timeout_ms = 60u * 1000u;
        if (nvme_admin(d->fd, &c, msg, msgsz) < 0) return FG_ERR_UNSUPPORTED;
        snprintf(msg, msgsz, "NVMe Sanitize (%s) started",
                 op == FG_FW_NVME_SANITIZE_CRYPTO ? "crypto erase" : "block erase");
        return FG_OK;
    }
    case FG_FW_TRIM_DISCARD: {
        uint64_t range[2];
        range[0] = 0; range[1] = d->size;
        if (ioctl(d->fd, BLKSECDISCARD, &range) == 0) {
            snprintf(msg, msgsz, "BLKSECDISCARD (secure TRIM) over %llu bytes",
                     (unsigned long long)d->size);
            return FG_OK;
        }
        range[0] = 0; range[1] = d->size;
        if (ioctl(d->fd, BLKDISCARD, &range) == 0) {
            snprintf(msg, msgsz, "BLKDISCARD (TRIM) over %llu bytes",
                     (unsigned long long)d->size);
            return FG_OK;
        }
        snprintf(msg, msgsz, "discard not supported: %s", strerror(errno));
        return FG_ERR_UNSUPPORTED;
    }
    }
    return FG_ERR_UNSUPPORTED;
#else
    FG_UNUSED(op);
    snprintf(msg, msgsz,
             "macOS does not expose ATA/NVMe pass-through to userspace without a "
             "kernel extension; overwrite-based sanitization will be used");
    return FG_ERR_UNSUPPORTED;
#endif
}

fg_status fg_dev_dismount_volumes(const char *device_id)
{
#if FG_LINUX
    /* Best effort: ask the kernel to re-read the partition table, which fails
     * while any partition is mounted - that is the signal we want. */
    int fd = open(device_id, O_RDONLY);
    if (fd < 0) return FG_ERR_NOTFOUND;
#  ifdef BLKRRPART
    if (ioctl(fd, BLKRRPART, 0) < 0 && errno == EBUSY) { close(fd); return FG_ERR_BUSY; }
#  endif
    close(fd);
    return FG_OK;
#else
    FG_UNUSED(device_id);
    return FG_OK;
#endif
}

/* ========================================================================== */
/*  device enumeration                                                        */
/* ========================================================================== */
static void trim_trailing(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n-1] == ' ' || s[n-1] == '\n' || s[n-1] == '\r')) s[--n] = '\0';
}

/* Reads one line from a sysfs attribute. Truncation is expected and fine:
 * the destinations are report fields, not parsing inputs. */
static int read_line_file(const char *path, char *out, size_t outsz)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    out[0] = '\0';
    if (!fgets(out, (int)outsz, f)) { fclose(f); return 0; }
    fclose(f);
    trim_trailing(out);
    return out[0] != '\0';
}

#if FG_LINUX
static void linux_mountpoints(const char *devname, char *out, size_t outsz, int *is_sys)
{
    FILE *f = fopen("/proc/mounts", "r");
    char line[1024];
    size_t used = 0;
    out[0] = '\0';
    *is_sys = 0;
    if (!f) return;
    while (fgets(line, sizeof line, f)) {
        char dev[256], mnt[512];
        if (sscanf(line, "%255s %511s", dev, mnt) != 2) continue;
        if (strncmp(dev, "/dev/", 5)) continue;
        if (strncmp(dev + 5, devname, strlen(devname))) continue;
        if (!strcmp(mnt, "/") || !strcmp(mnt, "/boot") ||
            !strcmp(mnt, "/boot/efi") || !strcmp(mnt, "/usr") || !strcmp(mnt, "/var"))
            *is_sys = 1;
        if (used + strlen(mnt) + 2 < outsz) {
            if (used) { out[used++] = ','; out[used] = '\0'; }
            memcpy(out + used, mnt, strlen(mnt) + 1);
            used += strlen(mnt);
        }
    }
    fclose(f);
}
#endif

int fg_dev_enumerate(fg_device_info *out, int max)
{
    int n = 0;
#if FG_LINUX
    DIR *dir = opendir("/sys/block");
    struct dirent *de;
    if (!dir) return FG_ERR_IO;
    while ((de = readdir(dir)) && n < max) {
        char p[512], v[256];
        fg_device_info *di;
        if (de->d_name[0] == '.') continue;
        /* Skip loop/ram/device-mapper pseudo devices. */
        if (!strncmp(de->d_name, "loop", 4) || !strncmp(de->d_name, "ram", 3) ||
            !strncmp(de->d_name, "dm-", 3) || !strncmp(de->d_name, "zram", 4) ||
            !strncmp(de->d_name, "md", 2)) continue;

        di = &out[n];
        memset(di, 0, sizeof *di);
        snprintf(di->id, sizeof di->id, "/dev/%.48s", de->d_name);

        snprintf(p, sizeof p, "/sys/block/%s/size", de->d_name);
        if (read_line_file(p, v, sizeof v)) di->size_bytes = strtoull(v, NULL, 10) * 512ull;
        if (!di->size_bytes) continue;

        snprintf(p, sizeof p, "/sys/block/%s/device/model", de->d_name);
        if (read_line_file(p, v, sizeof v)) snprintf(di->model, sizeof di->model, "%.72s", v);
        snprintf(p, sizeof p, "/sys/block/%s/device/serial", de->d_name);
        if (read_line_file(p, v, sizeof v)) snprintf(di->serial, sizeof di->serial, "%.72s", v);
        if (!di->serial[0]) {
            snprintf(p, sizeof p, "/sys/block/%s/serial", de->d_name);
            if (read_line_file(p, v, sizeof v)) snprintf(di->serial, sizeof di->serial, "%.72s", v);
        }
        snprintf(p, sizeof p, "/sys/block/%s/device/firmware_rev", de->d_name);
        if (read_line_file(p, v, sizeof v)) snprintf(di->firmware, sizeof di->firmware, "%.24s", v);

        snprintf(p, sizeof p, "/sys/block/%s/queue/logical_block_size", de->d_name);
        di->logical_sector = read_line_file(p, v, sizeof v) ? (uint32_t)atoi(v) : 512;
        snprintf(p, sizeof p, "/sys/block/%s/queue/physical_block_size", de->d_name);
        di->physical_sector = read_line_file(p, v, sizeof v) ? (uint32_t)atoi(v) : di->logical_sector;

        snprintf(p, sizeof p, "/sys/block/%s/queue/rotational", de->d_name);
        di->media = (read_line_file(p, v, sizeof v) && v[0] == '0') ? FG_MEDIA_SSD : FG_MEDIA_HDD;

        snprintf(p, sizeof p, "/sys/block/%s/removable", de->d_name);
        di->removable = (read_line_file(p, v, sizeof v) && v[0] == '1');

        snprintf(p, sizeof p, "/sys/block/%s/queue/discard_granularity", de->d_name);
        di->supports_trim = (read_line_file(p, v, sizeof v) && strtoull(v, NULL, 10) > 0);

        if (!strncmp(de->d_name, "nvme", 4)) {
            di->bus = FG_BUS_NVME; di->media = FG_MEDIA_SSD;
            di->supports_nvme_sanitize = 1;
        } else if (!strncmp(de->d_name, "mmcblk", 6)) {
            di->bus = FG_BUS_MMC; di->media = FG_MEDIA_FLASH;
        } else if (!strncmp(de->d_name, "sr", 2)) {
            di->bus = FG_BUS_SCSI; di->media = FG_MEDIA_OPTICAL;
        } else {
            di->bus = di->removable ? FG_BUS_USB : FG_BUS_SATA;
            di->supports_ata_secure_erase = !di->removable;
        }
        if (di->removable && di->media == FG_MEDIA_HDD) di->media = FG_MEDIA_FLASH;

        linux_mountpoints(de->d_name, di->mountpoints, sizeof di->mountpoints, &di->is_system);
        di->has_mounted_fs = di->mountpoints[0] != '\0';
        if (!di->model[0]) snprintf(di->model, sizeof di->model, "%s", "Unknown device");
        n++;
    }
    closedir(dir);
#elif FG_MACOS
    int i;
    for (i = 0; i < 32 && n < max; i++) {
        char path[64];
        int fd;
        fg_device_info *di;
        uint32_t bs = 0, solid = 0, virt = 0;
        uint64_t bc = 0;
        snprintf(path, sizeof path, "/dev/rdisk%d", i);
        fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        di = &out[n];
        memset(di, 0, sizeof *di);
        snprintf(di->id, sizeof di->id, "/dev/rdisk%d", i);
        if (ioctl(fd, DKIOCGETBLOCKSIZE, &bs) == 0 &&
            ioctl(fd, DKIOCGETBLOCKCOUNT, &bc) == 0) {
            di->logical_sector = bs ? bs : 512;
            di->physical_sector = di->logical_sector;
            di->size_bytes = (uint64_t)bs * bc;
        }
#  ifdef DKIOCISSOLIDSTATE
        if (ioctl(fd, DKIOCISSOLIDSTATE, &solid) == 0 && solid) di->media = FG_MEDIA_SSD;
        else di->media = FG_MEDIA_HDD;
#  endif
#  ifdef DKIOCISVIRTUAL
        if (ioctl(fd, DKIOCISVIRTUAL, &virt) == 0 && virt) di->bus = FG_BUS_VIRTUAL;
#  endif
        close(fd);
        if (!di->size_bytes) continue;
        snprintf(di->model, sizeof di->model, "Disk %d", i);
        if (i == 0) di->is_system = 1;
        {   /* mount points */
            struct statfs *mnt;
            int cnt = getmntinfo(&mnt, MNT_NOWAIT), k;
            size_t used = 0;
            for (k = 0; k < cnt; k++) {
                if (strncmp(mnt[k].f_mntfromname, di->id + 6, 0) == 0 &&
                    strstr(mnt[k].f_mntfromname, path + 6)) {
                    size_t l = strlen(mnt[k].f_mntonname);
                    if (used + l + 2 < sizeof di->mountpoints) {
                        if (used) di->mountpoints[used++] = ',';
                        memcpy(di->mountpoints + used, mnt[k].f_mntonname, l + 1);
                        used += l;
                    }
                    if (!strcmp(mnt[k].f_mntonname, "/")) di->is_system = 1;
                }
            }
            di->has_mounted_fs = di->mountpoints[0] != '\0';
        }
        n++;
    }
#endif
    return n;
}

fg_status fg_dev_probe(const char *path, fg_device_info *out)
{
    fg_device_info list[64];
    int n, i;
    struct stat st;
    memset(out, 0, sizeof *out);
    if (stat(path, &st) != 0) return FG_ERR_NOTFOUND;
    if (S_ISREG(st.st_mode)) {
        snprintf(out->id, sizeof out->id, "%s", path);
        snprintf(out->model, sizeof out->model, "Disk image file");
        out->size_bytes = (uint64_t)st.st_size;
        out->logical_sector = out->physical_sector = 512;
        out->media = FG_MEDIA_IMAGE;
        out->bus = FG_BUS_VIRTUAL;
        return FG_OK;
    }
    n = fg_dev_enumerate(list, 64);
    for (i = 0; i < n; i++) {
        if (!strcmp(list[i].id, path)) { *out = list[i]; return FG_OK; }
    }
    snprintf(out->id, sizeof out->id, "%s", path);
    {
        int fd = open(path, O_RDONLY);
        if (fd >= 0) { out->size_bytes = fd_block_size(fd, &out->logical_sector); close(fd); }
    }
    out->physical_sector = out->logical_sector;
    return out->size_bytes ? FG_OK : FG_ERR_NOTFOUND;
}

/* ========================================================================== */
/*  filesystem                                                                */
/* ========================================================================== */
fg_status fg_fs_stat(const char *path, fg_fs_entry *out)
{
    struct stat st;
    const char *base;
    memset(out, 0, sizeof *out);
    if (lstat(path, &st) != 0) return FG_ERR_NOTFOUND;
    snprintf(out->path, sizeof out->path, "%s", path);
    base = strrchr(path, '/');
    snprintf(out->name, sizeof out->name, "%s", base ? base + 1 : path);
    out->size       = (uint64_t)st.st_size;
    out->mtime      = (int64_t)st.st_mtime;
    out->atime      = (int64_t)st.st_atime;
    out->ctime      = (int64_t)st.st_ctime;
    out->is_dir     = S_ISDIR(st.st_mode) ? 1 : 0;
    out->is_symlink = S_ISLNK(st.st_mode) ? 1 : 0;
    out->is_readonly = (st.st_mode & S_IWUSR) ? 0 : 1;
    /* A file is sparse when it occupies fewer 512-byte blocks than its size. */
    out->is_sparse  = (!out->is_dir && st.st_size > 0 &&
                       (uint64_t)st.st_blocks * 512ull < (uint64_t)st.st_size) ? 1 : 0;
    return FG_OK;
}

int fg_fs_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

fg_status fg_fs_mkdirs(const char *path)
{
    char tmp[4096];
    size_t i, n;
    snprintf(tmp, sizeof tmp, "%s", path);
    n = strlen(tmp);
    while (n > 1 && tmp[n-1] == '/') tmp[--n] = '\0';
    for (i = 1; i < n; i++) {
        if (tmp[i] == '/') {
            tmp[i] = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return FG_ERR_IO;
            tmp[i] = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return FG_ERR_IO;
    return FG_OK;
}

fg_status fg_fs_remove(const char *path)
{ return unlink(path) == 0 ? FG_OK : (errno == ENOENT ? FG_ERR_NOTFOUND : FG_ERR_IO); }

fg_status fg_fs_rmdir(const char *path)
{ return rmdir(path) == 0 ? FG_OK : FG_ERR_IO; }

fg_status fg_fs_rename(const char *from, const char *to)
{ return rename(from, to) == 0 ? FG_OK : FG_ERR_IO; }

fg_status fg_fs_truncate(const char *path, uint64_t len)
{ return truncate(path, (off_t)len) == 0 ? FG_OK : FG_ERR_IO; }

fg_status fg_fs_set_times(const char *path, int64_t atime, int64_t mtime)
{
    struct utimbuf tb;
    tb.actime = (time_t)atime;
    tb.modtime = (time_t)mtime;
    return utime(path, &tb) == 0 ? FG_OK : FG_ERR_IO;
}

fg_status fg_fs_clear_attrs(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return FG_ERR_NOTFOUND;
    return chmod(path, (st.st_mode & 07777) | S_IWUSR) == 0 ? FG_OK : FG_ERR_IO;
}

fg_status fg_fs_free_space(const char *path, uint64_t *freeb, uint64_t *totalb, uint32_t *clus)
{
    struct statvfs s;
    if (statvfs(path, &s) != 0) return FG_ERR_IO;
    if (freeb)  *freeb  = (uint64_t)s.f_bavail * s.f_frsize;
    if (totalb) *totalb = (uint64_t)s.f_blocks * s.f_frsize;
    if (clus)   *clus   = (uint32_t)s.f_frsize;
    return FG_OK;
}

fg_status fg_fs_type(const char *path, char *out, size_t outsz)
{
#if FG_MACOS
    struct statfs s;
    if (statfs(path, &s) != 0) return FG_ERR_IO;
    snprintf(out, outsz, "%s", s.f_fstypename);
    return FG_OK;
#else
    FILE *f;
    char line[1024], best[64] = "unknown";
    size_t bestlen = 0;
    char real[4096];
    if (!realpath(path, real)) snprintf(real, sizeof real, "%s", path);
    f = fopen("/proc/mounts", "r");
    if (!f) { snprintf(out, outsz, "unknown"); return FG_OK; }
    while (fgets(line, sizeof line, f)) {
        char dev[256], mnt[512], type[64];
        size_t l;
        if (sscanf(line, "%255s %511s %63s", dev, mnt, type) != 3) continue;
        l = strlen(mnt);
        if (!strncmp(real, mnt, l) && l >= bestlen &&
            (real[l] == '\0' || real[l] == '/' || l == 1)) {
            bestlen = l;
            snprintf(best, sizeof best, "%s", type);
        }
    }
    fclose(f);
    snprintf(out, outsz, "%s", best);
    return FG_OK;
#endif
}

static fg_status walk_rec(const char *root, int recursive, fg_walk_fn cb, void *user, int *stop)
{
    DIR *d = opendir(root);
    struct dirent *de;
    if (!d) return FG_ERR_IO;
    while ((de = readdir(d)) && !*stop) {
        char child[4096];
        fg_fs_entry e;
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        snprintf(child, sizeof child, "%s/%s", root, de->d_name);
        if (fg_fs_stat(child, &e) != FG_OK) continue;
        if (cb(user, &e)) { *stop = 1; break; }
        if (e.is_dir && !e.is_symlink && recursive)
            walk_rec(child, recursive, cb, user, stop);
    }
    closedir(d);
    return FG_OK;
}

fg_status fg_fs_walk(const char *root, int recursive, fg_walk_fn cb, void *user)
{
    int stop = 0;
    return walk_rec(root, recursive, cb, user, &stop);
}

int fg_fs_wipe_alt_streams(const char *path)
{
#if FG_MACOS
    /* macOS resource forks live in an extended attribute; handled by xattrs. */
    FG_UNUSED(path);
    return 0;
#else
    FG_UNUSED(path);
    return 0;   /* NTFS-only concept */
#endif
}

int fg_fs_wipe_xattrs(const char *path)
{
    char list[8192];
    ssize_t n;
    int removed = 0;
    ssize_t i = 0;
#if FG_MACOS
    n = listxattr(path, list, sizeof list, XATTR_NOFOLLOW);
#else
    n = llistxattr(path, list, sizeof list);
#endif
    if (n <= 0) return 0;
    while (i < n) {
        const char *name = list + i;
#if FG_MACOS
        if (removexattr(path, name, XATTR_NOFOLLOW) == 0) removed++;
#else
        if (lremovexattr(path, name) == 0) removed++;
#endif
        i += (ssize_t)strlen(name) + 1;
    }
    return removed;
}

/* ---- file handles -------------------------------------------------------- */
struct fg_file { int fd; uint64_t size; };

fg_status fg_file_open_rw(const char *path, int direct, fg_file **out)
{
    fg_file *f;
    struct stat st;
    int flags = O_RDWR;
    *out = NULL;
#if FG_LINUX
    if (direct) flags |= O_SYNC;
#endif
    f = (fg_file *)fg_xcalloc(1, sizeof *f);
    if (!f) return FG_ERR_NOMEM;
    f->fd = open(path, flags);
    if (f->fd < 0) {
        free(f);
        return errno == EACCES ? FG_ERR_PERM :
               errno == ENOENT ? FG_ERR_NOTFOUND : FG_ERR_IO;
    }
#if FG_MACOS
    if (direct) fcntl(f->fd, F_NOCACHE, 1);
#endif
    if (fstat(f->fd, &st) == 0) f->size = (uint64_t)st.st_size;
    *out = f;
    return FG_OK;
}

fg_status fg_file_write_at(fg_file *f, const void *buf, size_t n, uint64_t off, size_t *put)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = n, total = 0;
    while (left) {
        ssize_t r = pwrite(f->fd, p, left, (off_t)(off + total));
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (!r) break;
        p += r; left -= (size_t)r; total += (size_t)r;
    }
    if (put) *put = total;
    return total == n ? FG_OK : FG_ERR_IO;
}

fg_status fg_file_read_at(fg_file *f, void *buf, size_t n, uint64_t off, size_t *got)
{
    uint8_t *p = (uint8_t *)buf;
    size_t left = n, total = 0;
    while (left) {
        ssize_t r = pread(f->fd, p, left, (off_t)(off + total));
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (!r) break;
        p += r; left -= (size_t)r; total += (size_t)r;
    }
    if (got) *got = total;
    return total ? FG_OK : FG_ERR_IO;
}

fg_status fg_file_sync(fg_file *f)
{
#if FG_MACOS
    if (fcntl(f->fd, F_FULLFSYNC, 0) == 0) return FG_OK;
#endif
    return fsync(f->fd) == 0 ? FG_OK : FG_ERR_IO;
}

uint64_t fg_file_size(fg_file *f) { return f ? f->size : 0; }

void fg_file_close(fg_file *f)
{
    if (!f) return;
    close(f->fd);
    free(f);
}

/* ========================================================================== */
/*  process / environment                                                     */
/* ========================================================================== */
int fg_is_elevated(void) { return geteuid() == 0; }

void fg_os_describe(char *out, size_t n)
{
    struct utsname u;
    if (uname(&u) == 0) snprintf(out, n, "%s %s %s", u.sysname, u.release, u.machine);
    else                snprintf(out, n, "POSIX");
}

void fg_hostname(char *out, size_t n)
{
    if (gethostname(out, n) != 0) snprintf(out, n, "unknown");
    out[n-1] = '\0';
}

void fg_username(char *out, size_t n)
{
    struct passwd *pw = getpwuid(geteuid());
    snprintf(out, n, "%s", (pw && pw->pw_name) ? pw->pw_name : "unknown");
}

fg_status fg_temp_dir(char *out, size_t n)
{
    const char *t = getenv("TMPDIR");
    snprintf(out, n, "%s", t && *t ? t : "/tmp");
    return FG_OK;
}

/* ========================================================================== */
/*  threads                                                                   */
/* ========================================================================== */
struct fg_thread { pthread_t t; };
struct fg_mutex  { pthread_mutex_t m; };

/* The entry point's arguments live in their own allocation, owned by the new
 * thread. If they lived in fg_thread, detaching the handle would free memory
 * the thread is still reading - a use-after-free that only shows up under
 * load, which is exactly when the dashboard is being used. */
typedef struct { void (*fn)(void *); void *arg; } fg_launch;

static void *thread_trampoline(void *p)
{
    fg_launch l = *(fg_launch *)p;
    free(p);
    l.fn(l.arg);
    return NULL;
}

fg_status fg_thread_start(fg_thread **out, void (*fn)(void *), void *arg)
{
    fg_thread *t = (fg_thread *)fg_xcalloc(1, sizeof *t);
    fg_launch *l;
    if (!t) return FG_ERR_NOMEM;
    l = (fg_launch *)fg_xcalloc(1, sizeof *l);
    if (!l) { free(t); return FG_ERR_NOMEM; }
    l->fn = fn; l->arg = arg;
    if (pthread_create(&t->t, NULL, thread_trampoline, l) != 0) {
        free(l);
        free(t);
        return FG_ERR_GENERIC;
    }
    *out = t;
    return FG_OK;
}

void fg_thread_join(fg_thread *t)
{
    if (!t) return;
    pthread_join(t->t, NULL);
    free(t);
}

void fg_thread_detach(fg_thread *t)
{
    if (!t) return;
    pthread_detach(t->t);
    free(t);
}

void fg_sleep_ms(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

fg_status fg_mutex_create(fg_mutex **out)
{
    fg_mutex *m = (fg_mutex *)fg_xcalloc(1, sizeof *m);
    if (!m) return FG_ERR_NOMEM;
    pthread_mutex_init(&m->m, NULL);
    *out = m;
    return FG_OK;
}
void fg_mutex_lock(fg_mutex *m)    { if (m) pthread_mutex_lock(&m->m); }
void fg_mutex_unlock(fg_mutex *m)  { if (m) pthread_mutex_unlock(&m->m); }
void fg_mutex_destroy(fg_mutex *m) { if (m) { pthread_mutex_destroy(&m->m); free(m); } }

/* ========================================================================== */
/*  sockets                                                                   */
/* ========================================================================== */
fg_status fg_net_startup(void) { return FG_OK; }
void      fg_net_cleanup(void) {}

fg_socket fg_net_listen(const char *bind_addr, int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    int one = 1;
    if (s < 0) return FG_INVALID_SOCKET;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = (bind_addr && strcmp(bind_addr, "0.0.0.0"))
                        ? inet_addr(bind_addr) : INADDR_ANY;
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0 || listen(s, 32) < 0) {
        close(s);
        return FG_INVALID_SOCKET;
    }
    return (fg_socket)s;
}

fg_socket fg_net_accept(fg_socket srv, char *peer, size_t peersz)
{
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    int c = accept((int)srv, (struct sockaddr *)&a, &al);
    if (c < 0) return FG_INVALID_SOCKET;
    if (peer && peersz) snprintf(peer, peersz, "%s", inet_ntoa(a.sin_addr));
    return (fg_socket)c;
}

int  fg_net_recv(fg_socket s, void *buf, int n) { return (int)recv((int)s, buf, (size_t)n, 0); }
int  fg_net_send(fg_socket s, const void *buf, int n)
{
#ifdef MSG_NOSIGNAL
    return (int)send((int)s, buf, (size_t)n, MSG_NOSIGNAL);
#else
    return (int)send((int)s, buf, (size_t)n, 0);
#endif
}
void fg_net_close(fg_socket s) { if (s != FG_INVALID_SOCKET) close((int)s); }

void fg_net_set_timeout(fg_socket s, int seconds)
{
    struct timeval tv;
    tv.tv_sec = seconds; tv.tv_usec = 0;
    setsockopt((int)s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt((int)s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

#endif /* !FG_WINDOWS */
