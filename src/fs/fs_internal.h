/* fs_internal.h - shared helpers between the filesystem parsers. Not installed. */
#ifndef FG_FS_INTERNAL_H
#define FG_FS_INTERNAL_H

#include "forge/fg_fs.h"

/* Windows FILETIME (100 ns ticks since 1601) -> unix seconds. */
static FG_INLINE int64_t fg_filetime_to_unix(uint64_t ft)
{
    if (!ft) return 0;
    return (int64_t)(ft / 10000000ull) - 11644473600ll;
}

/* Convert a UTF-16LE name of `chars` code units into UTF-8 (BMP only, which
 * covers every filename a report needs to display). */
void fg_utf16le_to_utf8(const uint8_t *src, int chars, char *out, size_t outsz);

/* Emit one recovered file into the scan result, extracting content when the
 * caller asked for files to be written. `runs` may be NULL for resident data,
 * in which case `resident` holds the bytes. */
typedef struct {
    uint64_t off;     /* absolute byte offset on the device */
    uint64_t len;
} fg_run;

fg_status fg_fs_emit(fg_fs_ctx *c, const char *name, fg_fs_kind fs,
                     const fg_run *runs, int nruns,
                     const uint8_t *resident, uint64_t size,
                     int64_t mtime, int deleted, int fragmented);

/* Load the NTFS $Bitmap; defined in ntfs.c and used by fg_alloc_map_load. */
fg_status fg_ntfs_load_bitmap(fg_fs_ctx *c, fg_alloc_map *m);

#endif
