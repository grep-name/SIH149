/* win32.c - Windows implementation of fg_platform.h (MinGW-w64 / MSVC). */
#include "forge/fg_platform.h"

#if FG_WINDOWS

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#  define _WIN32_WINNT 0x0601
#endif
#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <lmcons.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* MinGW headers sometimes omit these. */
#ifndef IOCTL_STORAGE_QUERY_PROPERTY
#  define IOCTL_STORAGE_QUERY_PROPERTY CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_SET_SPARSE
#  define FSCTL_SET_SPARSE CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 49, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#endif
#ifndef IOCTL_STORAGE_PROTOCOL_COMMAND
#  define IOCTL_STORAGE_PROTOCOL_COMMAND CTL_CODE(IOCTL_STORAGE_BASE, 0x04F0, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#endif

/* ========================================================================== */
/*  UTF-8 <-> UTF-16 helpers                                                  */
/* ========================================================================== */
static WCHAR *to_w(const char *s)
{
    int n;
    WCHAR *w;
    if (!s) return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    w = (WCHAR *)malloc((size_t)n * sizeof(WCHAR));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

static void from_w(const WCHAR *w, char *out, size_t outsz)
{
    if (!w) { if (outsz) out[0] = '\0'; return; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)outsz, NULL, NULL);
    out[outsz - 1] = '\0';
}

static fg_status last_error_status(void)
{
    DWORD e = GetLastError();
    switch (e) {
    case ERROR_ACCESS_DENIED:    return FG_ERR_PERM;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:   return FG_ERR_NOTFOUND;
    case ERROR_SHARING_VIOLATION:
    case ERROR_LOCK_VIOLATION:   return FG_ERR_BUSY;
    case ERROR_DISK_FULL:        return FG_ERR_RANGE;
    case ERROR_NOT_SUPPORTED:
    case ERROR_INVALID_FUNCTION: return FG_ERR_UNSUPPORTED;
    default:                     return FG_ERR_IO;
    }
}

/* ========================================================================== */
/*  device handle                                                             */
/* ========================================================================== */
/* FILE_FLAG_NO_BUFFERING imposes the same alignment rules as O_DIRECT: the
 * buffer, the length and the offset must all be multiples of the device block
 * size. A request that breaks them fails, and on a sanitization run that would
 * look exactly like a drive full of bad sectors. */
void *fg_aligned_alloc(size_t n)
{
    size_t rounded = (n + FG_IO_ALIGN - 1) & ~(size_t)(FG_IO_ALIGN - 1);
    return _aligned_malloc(rounded, FG_IO_ALIGN);
}

void fg_aligned_free(void *p) { if (p) _aligned_free(p); }

struct fg_dev {
    HANDLE   h;
    HANDLE   vol_locks[32];
    int      nlocks;
    char     path[512];
    uint64_t size;
    uint32_t sector;
    int      is_image;
    int      writable;
    int      direct;
};

static uint64_t disk_length(HANDLE h, uint32_t *sector)
{
    GET_LENGTH_INFORMATION li;
    DISK_GEOMETRY_EX gx;
    DWORD ret = 0;
    LARGE_INTEGER fsz;
    if (sector) *sector = 512;

    if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &li, sizeof li, &ret, NULL)) {
        if (DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, NULL, 0,
                            &gx, sizeof gx, &ret, NULL) && sector)
            *sector = gx.Geometry.BytesPerSector ? gx.Geometry.BytesPerSector : 512;
        return (uint64_t)li.Length.QuadPart;
    }
    if (GetFileSizeEx(h, &fsz)) return (uint64_t)fsz.QuadPart;
    return 0;
}

/* Lock and dismount every volume that lives on the physical drive so the
 * filesystem driver does not fight our raw writes. */
static void lock_volumes_of(struct fg_dev *d, int physical_index)
{
    WCHAR vol[MAX_PATH];
    HANDLE find = FindFirstVolumeW(vol, MAX_PATH);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        size_t len = wcslen(vol);
        HANDLE vh;
        DWORD ret = 0;
        BYTE buf[512];
        if (len && vol[len-1] == L'\\') vol[len-1] = L'\0';   /* trim for CreateFile */
        vh = CreateFileW(vol, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
        if (vh == INVALID_HANDLE_VALUE) continue;
        if (DeviceIoControl(vh, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
                            buf, sizeof buf, &ret, NULL)) {
            VOLUME_DISK_EXTENTS *ex = (VOLUME_DISK_EXTENTS *)buf;
            DWORD i;
            int match = 0;
            for (i = 0; i < ex->NumberOfDiskExtents; i++)
                if ((int)ex->Extents[i].DiskNumber == physical_index) match = 1;
            if (match && d->nlocks < 32) {
                DeviceIoControl(vh, FSCTL_LOCK_VOLUME, NULL, 0, NULL, 0, &ret, NULL);
                DeviceIoControl(vh, FSCTL_DISMOUNT_VOLUME, NULL, 0, NULL, 0, &ret, NULL);
                d->vol_locks[d->nlocks++] = vh;
                continue;      /* keep the handle open to hold the lock */
            }
        }
        CloseHandle(vh);
    } while (FindNextVolumeW(find, vol, MAX_PATH));
    FindVolumeClose(find);
}

static int physical_index_of(const char *path)
{
    const char *p = strstr(path, "PhysicalDrive");
    return p ? atoi(p + 13) : -1;
}

fg_status fg_dev_open(const char *path, int flags, fg_dev **out)
{
    fg_dev *d;
    DWORD access = 0, share = FILE_SHARE_READ | FILE_SHARE_WRITE, attrs = 0;
    WCHAR *wp;
    DWORD ftype;

    if (!path || !out) return FG_ERR_INVALID;
    *out = NULL;

    if (flags & FG_DEV_READ)  access |= GENERIC_READ;
    if (flags & FG_DEV_WRITE) access |= GENERIC_WRITE;
    if (flags & FG_DEV_DIRECT) attrs |= FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH;

    d = (fg_dev *)fg_xcalloc(1, sizeof *d);
    if (!d) return FG_ERR_NOMEM;

    wp = to_w(path);
    if (!wp) { free(d); return FG_ERR_NOMEM; }
    d->h = CreateFileW(wp, access, share, NULL, OPEN_EXISTING, attrs, NULL);
    if (d->h == INVALID_HANDLE_VALUE && (attrs & FILE_FLAG_NO_BUFFERING)) {
        attrs &= ~(DWORD)FILE_FLAG_NO_BUFFERING;
        d->h = CreateFileW(wp, access, share, NULL, OPEN_EXISTING, attrs, NULL);
    }
    free(wp);
    if (d->h == INVALID_HANDLE_VALUE) {
        fg_status st = last_error_status();
        free(d);
        return st;
    }

    snprintf(d->path, sizeof d->path, "%s", path);
    d->writable = (flags & FG_DEV_WRITE) ? 1 : 0;
    d->direct   = (attrs & FILE_FLAG_NO_BUFFERING) ? 1 : 0;
    ftype = GetFileType(d->h);
    d->is_image = (ftype == FILE_TYPE_DISK && strncmp(path, "\\\\.\\", 4) != 0);
    d->size = disk_length(d->h, &d->sector);
    if (d->is_image) d->sector = 512;

    if ((flags & FG_DEV_EXCL) && !d->is_image) {
        int idx = physical_index_of(path);
        if (idx >= 0) lock_volumes_of(d, idx);
    }
    *out = d;
    return FG_OK;
}

void fg_dev_close(fg_dev *d)
{
    int i;
    if (!d) return;
    if (d->writable) FlushFileBuffers(d->h);
    for (i = 0; i < d->nlocks; i++) {
        DWORD ret = 0;
        DeviceIoControl(d->vol_locks[i], FSCTL_UNLOCK_VOLUME, NULL, 0, NULL, 0, &ret, NULL);
        CloseHandle(d->vol_locks[i]);
    }
    CloseHandle(d->h);
    free(d);
}

uint64_t    fg_dev_size(const fg_dev *d)     { return d ? d->size : 0; }
uint32_t    fg_dev_sector(const fg_dev *d)   { return d ? d->sector : 512; }
const char *fg_dev_path(const fg_dev *d)     { return d ? d->path : ""; }
int         fg_dev_is_image(const fg_dev *d) { return d ? d->is_image : 0; }

static int needs_bounce(const fg_dev *d, const void *buf, size_t n, uint64_t off)
{
    uint32_t a = d->sector ? d->sector : 512;
    if (!d->direct) return 0;
    return ((uintptr_t)buf % FG_IO_ALIGN) != 0 || (n % a) != 0 || (off % a) != 0;
}

static fg_status pread_raw(fg_dev *d, void *buf, size_t n, uint64_t off, size_t *got)
{
    OVERLAPPED ov;
    DWORD rd = 0;
    size_t total = 0;
    uint8_t *p = (uint8_t *)buf;
    if (got) *got = 0;
    while (total < n) {
        DWORD want = (DWORD)FG_MIN(n - total, (size_t)0x7FFFF000u);
        memset(&ov, 0, sizeof ov);
        ov.Offset     = (DWORD)((off + total) & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)((off + total) >> 32);
        if (!ReadFile(d->h, p + total, want, &rd, &ov)) {
            if (GetLastError() == ERROR_HANDLE_EOF) break;
            if (got) *got = total;
            return total ? FG_OK : FG_ERR_IO;
        }
        if (!rd) break;
        total += rd;
    }
    if (got) *got = total;
    return total ? FG_OK : FG_ERR_IO;
}

static fg_status pwrite_raw(fg_dev *d, const void *buf, size_t n, uint64_t off, size_t *put)
{
    OVERLAPPED ov;
    DWORD wr = 0;
    size_t total = 0;
    const uint8_t *p = (const uint8_t *)buf;
    if (put) *put = 0;
    while (total < n) {
        DWORD want = (DWORD)FG_MIN(n - total, (size_t)0x7FFFF000u);
        memset(&ov, 0, sizeof ov);
        ov.Offset     = (DWORD)((off + total) & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)((off + total) >> 32);
        if (!WriteFile(d->h, p + total, want, &wr, &ov)) {
            fg_status st = last_error_status();
            if (put) *put = total;
            return st;
        }
        if (!wr) break;
        total += wr;
    }
    if (put) *put = total;
    return total == n ? FG_OK : FG_ERR_IO;
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
{ return FlushFileBuffers(d->h) ? FG_OK : FG_ERR_IO; }

/* ---- firmware sanitize --------------------------------------------------- */
/* ATA pass-through: SECURITY SET PASSWORD / ERASE PREPARE / ERASE UNIT. */
typedef struct {
    ATA_PASS_THROUGH_EX apt;
    UCHAR               buf[512];
} fg_ata_req;

static int ata_pt(HANDLE h, UCHAR cmd, UCHAR features, UCHAR sector_count,
                  void *data, ULONG datalen, int to_device, ULONG timeout_s)
{
    fg_ata_req req;
    DWORD ret = 0;
    BOOL ok;

    memset(&req, 0, sizeof req);
    req.apt.Length        = sizeof(ATA_PASS_THROUGH_EX);
    req.apt.TimeOutValue  = timeout_s;
    req.apt.AtaFlags      = (USHORT)(datalen ? (to_device ? ATA_FLAGS_DATA_OUT : ATA_FLAGS_DATA_IN)
                                             : 0);
    req.apt.DataTransferLength = datalen;
    req.apt.DataBufferOffset   = datalen ? (ULONG_PTR)offsetof(fg_ata_req, buf) : 0;
    req.apt.CurrentTaskFile[0] = features;
    req.apt.CurrentTaskFile[1] = sector_count;
    req.apt.CurrentTaskFile[6] = cmd;
    if (datalen && to_device && data) memcpy(req.buf, data, FG_MIN(datalen, 512u));

    ok = DeviceIoControl(h, IOCTL_ATA_PASS_THROUGH, &req, sizeof req,
                         &req, sizeof req, &ret, NULL);
    if (!ok) return -1;
    if (datalen && !to_device && data) memcpy(data, req.buf, FG_MIN(datalen, 512u));
    return 0;
}

fg_status fg_dev_firmware_sanitize(fg_dev *d, fg_fw_op op, char *msg, size_t msgsz)
{
    if (msg && msgsz) msg[0] = '\0';
    if (!d) return FG_ERR_INVALID;
    if (d->is_image) {
        snprintf(msg, msgsz, "source is a disk image; firmware commands do not apply");
        return FG_ERR_UNSUPPORTED;
    }
    switch (op) {
    case FG_FW_ATA_SECURE_ERASE:
    case FG_FW_ATA_SECURE_ERASE_ENHANCED: {
        UCHAR pwbuf[512];
        static const char pw[] = "ForgeTempPW";
        int enhanced = (op == FG_FW_ATA_SECURE_ERASE_ENHANCED);

        memset(pwbuf, 0, sizeof pwbuf);
        memcpy(pwbuf + 2, pw, sizeof pw - 1);
        if (ata_pt(d->h, 0xF1, 0, 1, pwbuf, 512, 1, 15) < 0) {
            snprintf(msg, msgsz, "ATA SECURITY SET PASSWORD rejected (error %lu); "
                                 "the drive may be in a FROZEN security state",
                     (unsigned long)GetLastError());
            return FG_ERR_UNSUPPORTED;
        }
        if (ata_pt(d->h, 0xF3, 0, 0, NULL, 0, 0, 15) < 0) {
            snprintf(msg, msgsz, "ATA SECURITY ERASE PREPARE failed");
            return FG_ERR_UNSUPPORTED;
        }
        memset(pwbuf, 0, sizeof pwbuf);
        pwbuf[0] = (UCHAR)(enhanced ? 0x02 : 0x00);
        memcpy(pwbuf + 2, pw, sizeof pw - 1);
        if (ata_pt(d->h, 0xF4, 0, 1, pwbuf, 512, 1, 12u * 3600u) < 0) {
            snprintf(msg, msgsz, "ATA SECURITY ERASE UNIT failed (error %lu)",
                     (unsigned long)GetLastError());
            return FG_ERR_UNSUPPORTED;
        }
        snprintf(msg, msgsz, "ATA SECURITY ERASE UNIT (%s) completed",
                 enhanced ? "enhanced" : "normal");
        return FG_OK;
    }
    case FG_FW_ATA_SANITIZE_BLOCK:
    case FG_FW_ATA_SANITIZE_CRYPTO: {
        int crypto = (op == FG_FW_ATA_SANITIZE_CRYPTO);
        if (ata_pt(d->h, 0xB4, (UCHAR)(crypto ? 0x11 : 0x12), 0, NULL, 0, 0, 60) < 0) {
            snprintf(msg, msgsz, "ATA SANITIZE not accepted by the device");
            return FG_ERR_UNSUPPORTED;
        }
        snprintf(msg, msgsz, "ATA SANITIZE %s issued",
                 crypto ? "CRYPTO SCRAMBLE" : "BLOCK ERASE");
        return FG_OK;
    }
    case FG_FW_TRIM_DISCARD: {
        DWORD ret = 0;
        /* Windows exposes TRIM on a whole disk only through a file-system
         * level operation; attempting it on \\.\PhysicalDrive is a no-op. */
        FG_UNUSED(ret);
        snprintf(msg, msgsz, "whole-device TRIM is not exposed by the Windows "
                             "storage stack; overwrite passes will be used");
        return FG_ERR_UNSUPPORTED;
    }
    default:
        snprintf(msg, msgsz,
                 "NVMe sanitize requires a vendor-specific pass-through on this "
                 "Windows build; overwrite-based sanitization will be used");
        return FG_ERR_UNSUPPORTED;
    }
}

fg_status fg_dev_dismount_volumes(const char *device_id)
{
    fg_dev *d = NULL;
    fg_status st = fg_dev_open(device_id, FG_DEV_READ | FG_DEV_WRITE | FG_DEV_EXCL, &d);
    if (st != FG_OK) return st;
    fg_dev_close(d);
    return FG_OK;
}

/* ========================================================================== */
/*  device enumeration                                                        */
/* ========================================================================== */
static void query_storage_property(HANDLE h, fg_device_info *di)
{
    STORAGE_PROPERTY_QUERY q;
    BYTE buf[2048];
    DWORD ret = 0;

    memset(&q, 0, sizeof q);
    q.PropertyId = StorageDeviceProperty;
    q.QueryType  = PropertyStandardQuery;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q,
                        buf, sizeof buf, &ret, NULL)) {
        STORAGE_DEVICE_DESCRIPTOR *sd = (STORAGE_DEVICE_DESCRIPTOR *)buf;
        if (sd->ProductIdOffset && sd->ProductIdOffset < ret)
            snprintf(di->model, sizeof di->model, "%s", (char *)buf + sd->ProductIdOffset);
        if (sd->SerialNumberOffset && sd->SerialNumberOffset < ret)
            snprintf(di->serial, sizeof di->serial, "%s", (char *)buf + sd->SerialNumberOffset);
        if (sd->ProductRevisionOffset && sd->ProductRevisionOffset < ret)
            snprintf(di->firmware, sizeof di->firmware, "%s", (char *)buf + sd->ProductRevisionOffset);
        di->removable = sd->RemovableMedia ? 1 : 0;
        switch (sd->BusType) {
        case BusTypeAta:   di->bus = FG_BUS_ATA;  di->supports_ata_secure_erase = 1; break;
        case BusTypeSata:  di->bus = FG_BUS_SATA; di->supports_ata_secure_erase = 1; break;
        case BusTypeScsi:  di->bus = FG_BUS_SCSI; break;
        case BusTypeUsb:   di->bus = FG_BUS_USB;  break;
        case BusTypeSd:    di->bus = FG_BUS_SD;   break;
        case BusTypeMmc:   di->bus = FG_BUS_MMC;  break;
        case BusTypeRAID:  di->bus = FG_BUS_RAID; break;
#ifdef BusTypeNvme
        case BusTypeNvme:  di->bus = FG_BUS_NVME; di->supports_nvme_sanitize = 1; break;
#endif
        default:           di->bus = FG_BUS_UNKNOWN; break;
        }
    }

    /* Seek penalty tells HDD from SSD. */
    memset(&q, 0, sizeof q);
    q.PropertyId = (STORAGE_PROPERTY_ID)7;   /* StorageDeviceSeekPenaltyProperty */
    q.QueryType  = PropertyStandardQuery;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q,
                        buf, sizeof buf, &ret, NULL) && ret >= 12) {
        BOOLEAN penalty = buf[8];
        di->media = penalty ? FG_MEDIA_HDD : FG_MEDIA_SSD;
    }
    if (di->media == FG_MEDIA_UNKNOWN)
        di->media = di->removable ? FG_MEDIA_FLASH : FG_MEDIA_HDD;

    memset(&q, 0, sizeof q);
    q.PropertyId = (STORAGE_PROPERTY_ID)8;   /* StorageDeviceTrimProperty */
    q.QueryType  = PropertyStandardQuery;
    if (DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q,
                        buf, sizeof buf, &ret, NULL) && ret >= 9)
        di->supports_trim = buf[8] ? 1 : 0;
}

static void drive_letters_for(int index, fg_device_info *di)
{
    DWORD mask = GetLogicalDrives();
    int i;
    size_t used = 0;
    UINT sysdrv_type;
    char sysdir[MAX_PATH] = "";
    GetSystemDirectoryA(sysdir, MAX_PATH);
    sysdrv_type = 0;
    FG_UNUSED(sysdrv_type);

    di->mountpoints[0] = '\0';
    for (i = 0; i < 26; i++) {
        char vol[8], dev[16];
        HANDLE vh;
        BYTE buf[512];
        DWORD ret = 0;
        if (!(mask & (1u << i))) continue;
        snprintf(vol, sizeof vol, "\\\\.\\%c:", 'A' + i);
        vh = CreateFileA(vol, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
        if (vh == INVALID_HANDLE_VALUE) continue;
        if (DeviceIoControl(vh, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, NULL, 0,
                            buf, sizeof buf, &ret, NULL)) {
            VOLUME_DISK_EXTENTS *ex = (VOLUME_DISK_EXTENTS *)buf;
            DWORD k;
            for (k = 0; k < ex->NumberOfDiskExtents; k++) {
                if ((int)ex->Extents[k].DiskNumber != index) continue;
                snprintf(dev, sizeof dev, "%c:", 'A' + i);
                if (used + 4 < sizeof di->mountpoints) {
                    if (used) di->mountpoints[used++] = ',';
                    memcpy(di->mountpoints + used, dev, strlen(dev) + 1);
                    used += strlen(dev);
                }
                di->has_mounted_fs = 1;
                if (sysdir[0] && (char)('A' + i) == sysdir[0]) di->is_system = 1;
            }
        }
        CloseHandle(vh);
    }
}

int fg_dev_enumerate(fg_device_info *out, int max)
{
    int i, n = 0;
    for (i = 0; i < 64 && n < max; i++) {
        char path[64];
        HANDLE h;
        fg_device_info *di;
        snprintf(path, sizeof path, "\\\\.\\PhysicalDrive%d", i);
        h = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        di = &out[n];
        memset(di, 0, sizeof *di);
        snprintf(di->id, sizeof di->id, "%s", path);
        di->size_bytes = disk_length(h, &di->logical_sector);
        di->physical_sector = di->logical_sector;
        query_storage_property(h, di);
        CloseHandle(h);
        if (!di->size_bytes) continue;
        if (!di->model[0]) snprintf(di->model, sizeof di->model, "Physical drive %d", i);
        drive_letters_for(i, di);
        n++;
    }
    return n;
}

fg_status fg_dev_probe(const char *path, fg_device_info *out)
{
    fg_device_info list[64];
    int n, i;
    memset(out, 0, sizeof *out);
    if (strncmp(path, "\\\\.\\", 4) != 0) {
        WIN32_FILE_ATTRIBUTE_DATA fa;
        WCHAR *wp = to_w(path);
        BOOL ok = wp && GetFileAttributesExW(wp, GetFileExInfoStandard, &fa);
        free(wp);
        if (!ok) return FG_ERR_NOTFOUND;
        snprintf(out->id, sizeof out->id, "%s", path);
        snprintf(out->model, sizeof out->model, "Disk image file");
        out->size_bytes = ((uint64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
        out->logical_sector = out->physical_sector = 512;
        out->media = FG_MEDIA_IMAGE;
        out->bus = FG_BUS_VIRTUAL;
        return FG_OK;
    }
    n = fg_dev_enumerate(list, 64);
    for (i = 0; i < n; i++)
        if (fg_strcaseeq(list[i].id, path)) { *out = list[i]; return FG_OK; }
    return FG_ERR_NOTFOUND;
}

/* ========================================================================== */
/*  filesystem                                                                */
/* ========================================================================== */
static int64_t ft_to_unix(const FILETIME *ft)
{
    ULARGE_INTEGER u;
    u.LowPart = ft->dwLowDateTime;
    u.HighPart = ft->dwHighDateTime;
    return (int64_t)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

static void unix_to_ft(int64_t t, FILETIME *ft)
{
    ULARGE_INTEGER u;
    u.QuadPart = (ULONGLONG)t * 10000000ULL + 116444736000000000ULL;
    ft->dwLowDateTime  = u.LowPart;
    ft->dwHighDateTime = u.HighPart;
}

fg_status fg_fs_stat(const char *path, fg_fs_entry *out)
{
    WIN32_FILE_ATTRIBUTE_DATA fa;
    WCHAR *wp;
    const char *base;
    BOOL ok;
    memset(out, 0, sizeof *out);
    wp = to_w(path);
    if (!wp) return FG_ERR_NOMEM;
    ok = GetFileAttributesExW(wp, GetFileExInfoStandard, &fa);
    free(wp);
    if (!ok) return FG_ERR_NOTFOUND;
    snprintf(out->path, sizeof out->path, "%s", path);
    base = strrchr(path, '\\');
    if (!base) base = strrchr(path, '/');
    snprintf(out->name, sizeof out->name, "%s", base ? base + 1 : path);
    out->size  = ((uint64_t)fa.nFileSizeHigh << 32) | fa.nFileSizeLow;
    out->mtime = ft_to_unix(&fa.ftLastWriteTime);
    out->atime = ft_to_unix(&fa.ftLastAccessTime);
    out->ctime = ft_to_unix(&fa.ftCreationTime);
    out->is_dir        = (fa.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
    out->is_symlink    = (fa.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ? 1 : 0;
    out->is_sparse     = (fa.dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE) ? 1 : 0;
    out->is_readonly   = (fa.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? 1 : 0;
    out->is_compressed = (fa.dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED) ? 1 : 0;
    out->is_encrypted  = (fa.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED) ? 1 : 0;
    return FG_OK;
}

int fg_fs_exists(const char *path)
{
    WCHAR *wp = to_w(path);
    DWORD a = wp ? GetFileAttributesW(wp) : INVALID_FILE_ATTRIBUTES;
    free(wp);
    return a != INVALID_FILE_ATTRIBUTES;
}

fg_status fg_fs_mkdirs(const char *path)
{
    char tmp[4096];
    size_t i, n;
    snprintf(tmp, sizeof tmp, "%s", path);
    n = strlen(tmp);
    while (n > 1 && (tmp[n-1] == '\\' || tmp[n-1] == '/')) tmp[--n] = '\0';
    for (i = 1; i < n; i++) {
        if (tmp[i] == '\\' || tmp[i] == '/') {
            char save = tmp[i];
            WCHAR *wp;
            tmp[i] = '\0';
            if (!(strlen(tmp) == 2 && tmp[1] == ':')) {
                wp = to_w(tmp);
                if (wp) { CreateDirectoryW(wp, NULL); free(wp); }
            }
            tmp[i] = save;
        }
    }
    {
        WCHAR *wp = to_w(tmp);
        BOOL ok = wp && (CreateDirectoryW(wp, NULL) ||
                         GetLastError() == ERROR_ALREADY_EXISTS);
        free(wp);
        return ok ? FG_OK : FG_ERR_IO;
    }
}

fg_status fg_fs_remove(const char *path)
{
    WCHAR *wp = to_w(path);
    BOOL ok;
    if (!wp) return FG_ERR_NOMEM;
    SetFileAttributesW(wp, FILE_ATTRIBUTE_NORMAL);
    ok = DeleteFileW(wp);
    free(wp);
    return ok ? FG_OK : last_error_status();
}

fg_status fg_fs_rmdir(const char *path)
{
    WCHAR *wp = to_w(path);
    BOOL ok = wp && RemoveDirectoryW(wp);
    free(wp);
    return ok ? FG_OK : FG_ERR_IO;
}

fg_status fg_fs_rename(const char *from, const char *to)
{
    WCHAR *wf = to_w(from), *wt = to_w(to);
    BOOL ok = wf && wt && MoveFileExW(wf, wt, MOVEFILE_REPLACE_EXISTING);
    free(wf); free(wt);
    return ok ? FG_OK : FG_ERR_IO;
}

fg_status fg_fs_truncate(const char *path, uint64_t len)
{
    WCHAR *wp = to_w(path);
    HANDLE h;
    LARGE_INTEGER li;
    if (!wp) return FG_ERR_NOMEM;
    h = CreateFileW(wp, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    free(wp);
    if (h == INVALID_HANDLE_VALUE) return last_error_status();
    li.QuadPart = (LONGLONG)len;
    SetFilePointerEx(h, li, NULL, FILE_BEGIN);
    SetEndOfFile(h);
    CloseHandle(h);
    return FG_OK;
}

fg_status fg_fs_set_times(const char *path, int64_t atime, int64_t mtime)
{
    WCHAR *wp = to_w(path);
    HANDLE h;
    FILETIME fa, fm;
    if (!wp) return FG_ERR_NOMEM;
    h = CreateFileW(wp, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    free(wp);
    if (h == INVALID_HANDLE_VALUE) return last_error_status();
    unix_to_ft(atime, &fa);
    unix_to_ft(mtime, &fm);
    SetFileTime(h, &fm, &fa, &fm);
    CloseHandle(h);
    return FG_OK;
}

fg_status fg_fs_clear_attrs(const char *path)
{
    WCHAR *wp = to_w(path);
    BOOL ok = wp && SetFileAttributesW(wp, FILE_ATTRIBUTE_NORMAL);
    free(wp);
    return ok ? FG_OK : FG_ERR_IO;
}

fg_status fg_fs_free_space(const char *path, uint64_t *freeb, uint64_t *totalb, uint32_t *clus)
{
    char root[MAX_PATH];
    ULARGE_INTEGER avail, total, tfree;
    DWORD spc = 0, bps = 0, nfc = 0, tnc = 0;
    snprintf(root, sizeof root, "%s", path);
    if (strlen(root) >= 2 && root[1] == ':') root[2] = '\\', root[3] = '\0';
    if (!GetDiskFreeSpaceExA(root, &avail, &total, &tfree)) return FG_ERR_IO;
    if (freeb)  *freeb  = (uint64_t)avail.QuadPart;
    if (totalb) *totalb = (uint64_t)total.QuadPart;
    if (clus) {
        *clus = 4096;
        if (GetDiskFreeSpaceA(root, &spc, &bps, &nfc, &tnc)) *clus = spc * bps;
    }
    return FG_OK;
}

fg_status fg_fs_type(const char *path, char *out, size_t outsz)
{
    char root[MAX_PATH];
    char fsname[64] = "unknown";
    snprintf(root, sizeof root, "%s", path);
    if (strlen(root) >= 2 && root[1] == ':') root[2] = '\\', root[3] = '\0';
    GetVolumeInformationA(root, NULL, 0, NULL, NULL, NULL, fsname, sizeof fsname);
    snprintf(out, outsz, "%s", fsname);
    return FG_OK;
}

static fg_status walk_rec(const char *root, int recursive, fg_walk_fn cb, void *user, int *stop)
{
    char pat[4096];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    WCHAR *wp;
    snprintf(pat, sizeof pat, "%s\\*", root);
    wp = to_w(pat);
    if (!wp) return FG_ERR_NOMEM;
    h = FindFirstFileW(wp, &fd);
    free(wp);
    if (h == INVALID_HANDLE_VALUE) return FG_ERR_IO;
    do {
        char name[512], child[4096];
        fg_fs_entry e;
        from_w(fd.cFileName, name, sizeof name);
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        snprintf(child, sizeof child, "%s\\%s", root, name);
        if (fg_fs_stat(child, &e) != FG_OK) continue;
        if (cb(user, &e)) { *stop = 1; break; }
        if (e.is_dir && !e.is_symlink && recursive)
            walk_rec(child, recursive, cb, user, stop);
    } while (!*stop && FindNextFileW(h, &fd));
    FindClose(h);
    return FG_OK;
}

fg_status fg_fs_walk(const char *root, int recursive, fg_walk_fn cb, void *user)
{
    int stop = 0;
    return walk_rec(root, recursive, cb, user, &stop);
}

/* NTFS alternate data streams are a classic hiding place and survive a naive
 * delete of the main stream, so they are enumerated and zeroed explicitly. */
int fg_fs_wipe_alt_streams(const char *path)
{
    WIN32_FIND_STREAM_DATA sd;
    HANDLE h;
    WCHAR *wp = to_w(path);
    int removed = 0;
    if (!wp) return 0;
    h = FindFirstStreamW(wp, FindStreamInfoStandard, &sd, 0);
    if (h == INVALID_HANDLE_VALUE) { free(wp); return 0; }
    do {
        char sname[512], full[5120];
        HANDLE sh;
        from_w(sd.cStreamName, sname, sizeof sname);
        if (!strcmp(sname, "::$DATA")) continue;      /* the main stream */
        snprintf(full, sizeof full, "%s%s", path, sname);
        {
            WCHAR *wf = to_w(full);
            if (wf) {
                sh = CreateFileW(wf, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
                if (sh != INVALID_HANDLE_VALUE) {
                    /* Overwrite the stream before unlinking it. */
                    LONGLONG left = sd.StreamSize.QuadPart;
                    BYTE zb[4096];
                    DWORD wr;
                    memset(zb, 0, sizeof zb);
                    while (left > 0) {
                        DWORD want = (DWORD)FG_MIN((LONGLONG)sizeof zb, left);
                        if (!WriteFile(sh, zb, want, &wr, NULL)) break;
                        left -= wr;
                    }
                    FlushFileBuffers(sh);
                    CloseHandle(sh);
                }
                if (DeleteFileW(wf)) removed++;
                free(wf);
            }
        }
    } while (FindNextStreamW(h, &sd));
    FindClose(h);
    free(wp);
    return removed;
}

int fg_fs_wipe_xattrs(const char *path) { FG_UNUSED(path); return 0; }

/* ---- file handles -------------------------------------------------------- */
struct fg_file { HANDLE h; uint64_t size; };

fg_status fg_file_open_rw(const char *path, int direct, fg_file **out)
{
    fg_file *f;
    WCHAR *wp;
    LARGE_INTEGER sz;
    DWORD attrs = direct ? FILE_FLAG_WRITE_THROUGH : 0;
    *out = NULL;
    f = (fg_file *)fg_xcalloc(1, sizeof *f);
    if (!f) return FG_ERR_NOMEM;
    wp = to_w(path);
    if (!wp) { free(f); return FG_ERR_NOMEM; }
    SetFileAttributesW(wp, FILE_ATTRIBUTE_NORMAL);
    f->h = CreateFileW(wp, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       OPEN_EXISTING, attrs, NULL);
    free(wp);
    if (f->h == INVALID_HANDLE_VALUE) { fg_status st = last_error_status(); free(f); return st; }
    if (GetFileSizeEx(f->h, &sz)) f->size = (uint64_t)sz.QuadPart;
    *out = f;
    return FG_OK;
}

fg_status fg_file_write_at(fg_file *f, const void *buf, size_t n, uint64_t off, size_t *put)
{
    OVERLAPPED ov;
    DWORD wr = 0;
    size_t total = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (total < n) {
        DWORD want = (DWORD)FG_MIN(n - total, (size_t)0x7FFFF000u);
        memset(&ov, 0, sizeof ov);
        ov.Offset     = (DWORD)((off + total) & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)((off + total) >> 32);
        if (!WriteFile(f->h, p + total, want, &wr, &ov) || !wr) break;
        total += wr;
    }
    if (put) *put = total;
    return total == n ? FG_OK : FG_ERR_IO;
}

fg_status fg_file_read_at(fg_file *f, void *buf, size_t n, uint64_t off, size_t *got)
{
    OVERLAPPED ov;
    DWORD rd = 0;
    size_t total = 0;
    uint8_t *p = (uint8_t *)buf;
    while (total < n) {
        DWORD want = (DWORD)FG_MIN(n - total, (size_t)0x7FFFF000u);
        memset(&ov, 0, sizeof ov);
        ov.Offset     = (DWORD)((off + total) & 0xFFFFFFFFu);
        ov.OffsetHigh = (DWORD)((off + total) >> 32);
        if (!ReadFile(f->h, p + total, want, &rd, &ov) || !rd) break;
        total += rd;
    }
    if (got) *got = total;
    return total ? FG_OK : FG_ERR_IO;
}

fg_status fg_file_sync(fg_file *f) { return FlushFileBuffers(f->h) ? FG_OK : FG_ERR_IO; }
uint64_t  fg_file_size(fg_file *f) { return f ? f->size : 0; }
void      fg_file_close(fg_file *f) { if (f) { CloseHandle(f->h); free(f); } }

/* ========================================================================== */
/*  process / environment                                                     */
/* ========================================================================== */
int fg_is_elevated(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION el;
    DWORD sz = sizeof el;
    BOOL ok = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof el, &sz))
            ok = el.TokenIsElevated ? TRUE : FALSE;
        CloseHandle(tok);
    }
    return ok ? 1 : 0;
}

void fg_os_describe(char *out, size_t n)
{
    SYSTEM_INFO si;
    DWORD ver = 0;
    OSVERSIONINFOEXA ov;
    const char *arch;
    GetNativeSystemInfo(&si);
    arch = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" :
           (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) ? "arm64" : "x86";
    memset(&ov, 0, sizeof ov);
    ov.dwOSVersionInfoSize = sizeof ov;
    /* GetVersionEx is deprecated and lies without a manifest; read the build
     * number from the registry-backed API instead. */
    {
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOEXA *);
        RtlGetVersion_t rgv = nt ? (RtlGetVersion_t)(void *)GetProcAddress(nt, "RtlGetVersion") : NULL;
        if (rgv) rgv(&ov);
    }
    ver = ov.dwBuildNumber;
    snprintf(out, n, "Windows %lu.%lu (build %lu) %s",
             (unsigned long)ov.dwMajorVersion, (unsigned long)ov.dwMinorVersion,
             (unsigned long)ver, arch);
}

void fg_hostname(char *out, size_t n)
{
    DWORD sz = (DWORD)n;
    if (!GetComputerNameA(out, &sz)) snprintf(out, n, "unknown");
}

void fg_username(char *out, size_t n)
{
    DWORD sz = (DWORD)n;
    if (!GetUserNameA(out, &sz)) snprintf(out, n, "unknown");
}

fg_status fg_temp_dir(char *out, size_t n)
{
    DWORD r = GetTempPathA((DWORD)n, out);
    if (!r) { snprintf(out, n, "."); return FG_ERR_IO; }
    if (r && out[r-1] == '\\') out[r-1] = '\0';
    return FG_OK;
}

/* ========================================================================== */
/*  threads                                                                   */
/* ========================================================================== */
struct fg_thread { HANDLE h; };
struct fg_mutex  { CRITICAL_SECTION cs; };

/* See the note in posix.c: the entry arguments must outlive the handle, so
 * they get their own allocation that the new thread owns. */
typedef struct { void (*fn)(void *); void *arg; } fg_launch;

static DWORD WINAPI thread_trampoline(LPVOID p)
{
    fg_launch l = *(fg_launch *)p;
    free(p);
    l.fn(l.arg);
    return 0;
}

fg_status fg_thread_start(fg_thread **out, void (*fn)(void *), void *arg)
{
    fg_thread *t = (fg_thread *)fg_xcalloc(1, sizeof *t);
    fg_launch *l;
    if (!t) return FG_ERR_NOMEM;
    l = (fg_launch *)fg_xcalloc(1, sizeof *l);
    if (!l) { free(t); return FG_ERR_NOMEM; }
    l->fn = fn; l->arg = arg;
    t->h = CreateThread(NULL, 0, thread_trampoline, l, 0, NULL);
    if (!t->h) { free(l); free(t); return FG_ERR_GENERIC; }
    *out = t;
    return FG_OK;
}

void fg_thread_join(fg_thread *t)
{
    if (!t) return;
    WaitForSingleObject(t->h, INFINITE);
    CloseHandle(t->h);
    free(t);
}

void fg_thread_detach(fg_thread *t) { if (t) { CloseHandle(t->h); free(t); } }
void fg_sleep_ms(unsigned ms) { Sleep(ms); }

fg_status fg_mutex_create(fg_mutex **out)
{
    fg_mutex *m = (fg_mutex *)fg_xcalloc(1, sizeof *m);
    if (!m) return FG_ERR_NOMEM;
    InitializeCriticalSection(&m->cs);
    *out = m;
    return FG_OK;
}
void fg_mutex_lock(fg_mutex *m)    { if (m) EnterCriticalSection(&m->cs); }
void fg_mutex_unlock(fg_mutex *m)  { if (m) LeaveCriticalSection(&m->cs); }
void fg_mutex_destroy(fg_mutex *m) { if (m) { DeleteCriticalSection(&m->cs); free(m); } }

/* ========================================================================== */
/*  sockets                                                                   */
/* ========================================================================== */
fg_status fg_net_startup(void)
{
    WSADATA wd;
    return WSAStartup(MAKEWORD(2, 2), &wd) == 0 ? FG_OK : FG_ERR_GENERIC;
}
void fg_net_cleanup(void) { WSACleanup(); }

fg_socket fg_net_listen(const char *bind_addr, int port)
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a;
    BOOL one = TRUE;
    if (s == INVALID_SOCKET) return FG_INVALID_SOCKET;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof one);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = (bind_addr && strcmp(bind_addr, "0.0.0.0"))
                        ? inet_addr(bind_addr) : INADDR_ANY;
    if (bind(s, (struct sockaddr *)&a, sizeof a) == SOCKET_ERROR ||
        listen(s, 32) == SOCKET_ERROR) {
        closesocket(s);
        return FG_INVALID_SOCKET;
    }
    return (fg_socket)s;
}

fg_socket fg_net_accept(fg_socket srv, char *peer, size_t peersz)
{
    struct sockaddr_in a;
    int al = sizeof a;
    SOCKET c = accept((SOCKET)srv, (struct sockaddr *)&a, &al);
    if (c == INVALID_SOCKET) return FG_INVALID_SOCKET;
    if (peer && peersz) snprintf(peer, peersz, "%s", inet_ntoa(a.sin_addr));
    return (fg_socket)c;
}

int  fg_net_recv(fg_socket s, void *buf, int n) { return recv((SOCKET)s, (char *)buf, n, 0); }
int  fg_net_send(fg_socket s, const void *buf, int n) { return send((SOCKET)s, (const char *)buf, n, 0); }
void fg_net_close(fg_socket s) { if (s != FG_INVALID_SOCKET) closesocket((SOCKET)s); }

void fg_net_set_timeout(fg_socket s, int seconds)
{
    DWORD ms = (DWORD)seconds * 1000u;
    setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof ms);
    setsockopt((SOCKET)s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof ms);
}

#endif /* FG_WINDOWS */
