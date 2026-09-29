# FORGE — Technical Documentation

SIH PS 26149 · NTRO · Version 1.0.0

---

## 1. Design constraints that shaped everything else

Three constraints drove the architecture:

**It must run where the evidence is.** A forensic workstation is often a live
boot stick with no network and no package manager. That rules out linking
OpenSSL, zlib, libcurl or a GUI toolkit. Every primitive FORGE needs —
SHA-256, MD5, HMAC, a CSPRNG, JSON, an HTTP server — is implemented in-tree,
roughly 13,000 lines of C11 with no external dependency.

**It must be auditable.** A tool that produces a certificate saying "this drive
was sanitized" is only as trustworthy as the code behind the claim. Everything
that touches the claim — pattern generation, verification, hashing, the audit
chain — is short enough to read and covered by known-answer tests in
`forge selftest`.

**It must not lie.** A carver that reports a 36 MiB "recovered JPEG" that is
actually random noise is worse than one that reports nothing, because an
investigator will spend an hour on it. Confidence scoring is therefore not
decoration: an extent with no structural corroboration is capped below the
default reporting threshold, on purpose.

## 2. Layering

```
  src/cli/main.c          command line
  src/ui/                 HTTP server + job manager  ──┐
                                                       ├─ both drive the same engine
  src/erase/  src/carve/  src/fs/   src/report/      ──┘
  src/core/               SHA-256, MD5, HMAC, ChaCha20, JSON, buffers
  src/platform/           win32.c | posix.c   ← the only OS-aware code
```

`include/forge/fg_platform.h` is the contract. Above it there is not a single
`#ifdef _WIN32`. Below it, `win32.c` and `posix.c` implement the same 60-odd
functions: raw device enumeration and positional I/O, firmware sanitize
pass-through, filesystem walking, alternate-data-stream and extended-attribute
removal, threads, mutexes and sockets.

## 3. Core primitives

### 3.1 The CSPRNG, and why ChaCha20

A single random-pass overwrite of a 2 TB drive needs 2 TB of unpredictable
bytes. No operating system CSPRNG will supply that at disk speed — and a tool
that quietly falls back to `rand()` has silently downgraded the sanitization.

FORGE takes a 256-bit seed from the OS (`BCryptGenRandom` / `getrandom(2)` /
`arc4random_buf`) and expands it with ChaCha20. The keystream is
cryptographically indistinguishable from random, which is exactly and only what
an overwrite pass requires, and it runs at memory bandwidth.

### 3.2 Entropy measurement without libm

Verification of a random pass checks Shannon entropy. `fg_shannon_entropy`
computes `log2` from `frexp`-style exponent extraction plus an `atanh` series,
so the library does not drag in a `libm` dependency that some MinGW
configurations make awkward.

## 4. Module 1 — Secure Drive Eraser

### 4.1 The pattern engine

`src/erase/patterns.c` declares every supported standard as a table of passes.
Each pass is `{kind, bytes[3], verify}` where kind is FIXED, TRIPLE (Gutmann's
3-byte groups), RANDOM or COMPLEMENT.

Two properties matter for verification:

- **Deterministic passes can be regenerated.** `fg_pattern_fill(def, pass, rng,
  buf, n, offset)` reproduces exactly the bytes that pass wrote at that offset,
  so verification is a byte-for-byte comparison rather than a heuristic.
- **Triple patterns are phase-aligned to the absolute device offset.** Without
  this, a verification read starting at an arbitrary offset would compare
  against a differently-phased pattern and report spurious mismatches.

| id | Standard | Passes |
|---|---|---|
| `zero` / `ones` / `random` | single pass | 1 |
| `nist-clear` | NIST SP 800-88 Rev.1, Clear | 1 + full verify |
| `nist-purge` | NIST SP 800-88 Rev.1, Purge | firmware, else 1 + verify |
| `dod3` | US DoD 5220.22-M | 3 |
| `dod7` | DoD 5220.22-M ECE | 7 |
| `vsitr` | German BSI-VSITR | 7 |
| `hmg` | UK HMG IS5 Enhanced | 3 |
| `gost` | GOST R 50739-95 | 2 |
| `schneier` | Schneier, *Applied Cryptography* 2e | 7 |
| `gutmann` | Gutmann 1996 | 35 |
| `crypto` | Cryptographic erase (firmware only) | — |

### 4.2 Firmware sanitize

For `nist-purge` and `crypto`, FORGE tries the device's own sanitize command
before overwriting anything, because on an SSD that is the only operation that
reaches over-provisioned and remapped blocks.

- **Linux** — ATA SECURITY ERASE UNIT and ATA SANITIZE through `SG_IO` ATA-16
  pass-through; NVMe Format NVM (SES=1/2) and NVMe Sanitize through
  `NVME_IOCTL_ADMIN_CMD`; `BLKSECDISCARD`/`BLKDISCARD` for secure TRIM.
- **Windows** — the same ATA commands through `IOCTL_ATA_PASS_THROUGH`.
- **macOS** — no userspace pass-through exists without a kernel extension. The
  attempt returns `FG_ERR_UNSUPPORTED` with an explanatory message that is
  printed on the certificate, and overwriting proceeds.

A refused firmware command is never silently swallowed: `crypto` fails loudly
rather than pretending, and `nist-purge` records in `firmware_detail` exactly
why it fell back.

### 4.3 Verification

`FG_VERIFY_FULL` reads every sector back. For a deterministic final pass it is a
byte comparison; for a random final pass it measures entropy over 64 KiB
windows and requires ≥ 7.90 bits/byte, since structured surviving data would
drag the figure down.

`FG_VERIFY_SAMPLE` (the default) reads 4096 windows of 64 KiB: the first, the
last, and the rest at CSPRNG-chosen offsets. That is enough to make any residual
region larger than ~0.01 % of the device overwhelmingly likely to be caught,
at a small fraction of the time a full pass costs. The certificate states the
mode, the byte count, the coverage percentage and a SHA-256 over everything
that was examined.

### 4.4 Bad sectors

Unwritable sectors are counted and the first offset recorded, and the wipe
continues — a failing drive is exactly when you most want the rest sanitized.
Past 65,536 unwritable sectors the operation aborts and says the device is
failing. The HTML certificate carries a remarks section explaining that
host-level overwriting cannot address sectors the drive has retired.

### 4.5 Safety interlocks

In order: refuse the disk holding the running OS; refuse a disk with mounted
volumes; require a confirmation token equal to the device serial number or the
literal word `ERASE`; require elevation. Each is overridable with an explicit
flag, and every refusal is written to the audit log as a `refused` event.

## 5. Module 2 — Secure File and Folder Eraser

Deleting a file removes a directory entry. The content stays on the platter and
so does a surprising amount of metadata. For each target, in this order:

1. **Alternate data streams and extended attributes first.** NTFS ADS are
   enumerated with `FindFirstStreamW`, each stream is overwritten with zeros
   before being unlinked. POSIX xattrs go through `llistxattr`/`lremovexattr`
   (`XATTR_NOFOLLOW` on macOS, which also covers resource forks). These go first
   so that an interrupted operation has at least destroyed the hidden copies.
2. **The data stream**, one full pass at a time, with an explicit flush to the
   medium after each. Without the flush the page cache coalesces the passes and
   only the last one ever reaches the disk — a subtle way for a multi-pass wipe
   to be a single-pass wipe.
3. **Cluster slack.** The tail of the last cluster is invisible to normal file
   APIs and holds whatever was there before. The file is grown to the cluster
   boundary, that region is overwritten, then it is truncated back.
4. **Staged truncation**, quartering the length repeatedly, so the filesystem
   cannot hand the whole run back with the original length still in metadata.
5. **Rename through shrinking random names**, five times, overwriting the
   original filename in the directory entry — the residue a plain `unlink`
   leaves behind.
6. **Timestamps zeroed**, then unlink.

### 5.1 Verifying a random final pass

This is subtler than it looks. A deterministic pass is checked byte-for-byte.
A random pass cannot be regenerated, so the obvious test is entropy — but
eleven random bytes cannot carry more than log2(11) ≈ 3.46 bits per byte, so an
entropy threshold fails every small file. (This was a real bug, caught in
testing, and is now covered by the end-to-end test.)

FORGE therefore checks two independent things: the sampled content must differ
from a digest taken *before* the overwrite (proof something was written), and,
only when the sample is at least 4096 bytes, it must also look like noise.

### 5.2 Free-space wiping

Everything deleted before FORGE was installed still sits in unallocated
clusters. `erase freespace` fills the volume with pattern data in 1 GiB files,
leaving a 32 MiB margin so the OS does not fall over, then creates thousands of
small padded files to consume the directory-entry and MFT-record space that
holds the names and resident content of small deleted files, then releases
everything.

## 6. Module 3 — Advanced File Carving and Recovery

Three strategies, strongest evidence first.

### 6.1 Filesystem metadata recovery

This is the strongest form of recovery because it returns the original name,
path, timestamps and fragmentation, not just a byte range.

**NTFS** (`src/fs/ntfs.c`) — `$MFT` is located from the boot sector, then its
own `$DATA` run list is decoded so a fragmented `$MFT` is followed correctly.
Every record is fixed up (the update-sequence array steals the last two bytes of
each sector; without putting them back the record is subtly corrupt), then
records with the IN_USE flag cleared are extracted. Resident data — small files
living entirely inside the record — survives a delete completely intact.
Non-resident data comes from the mapping-pair run list, which is why NTFS
recovery reconstructs fragmented files correctly where carving cannot. The
`$FILE_NAME` attribute is chosen by namespace so the Win32 long name wins over
the 8.3 short name.

**FAT12/16/32** (`src/fs/fat.c`) — deleted entries keep the starting cluster and
the exact size; only the first character of the name and the FAT chain are
destroyed. The chain being gone means contiguity has to be assumed, which is the
standard assumption for FAT recovery and is reflected in the confidence score.
Long filenames are reassembled from the LFN entry chain. Live subdirectories are
descended so deleted entries inside them are found.

**exFAT** — entry sets of 0x85 (file) + 0xC0 (stream extension) + 0xC1 (name).
The stream extension carries a "no FAT chain" flag that states outright whether
the file was contiguous, which makes exFAT recovery more reliable than FAT.

**ext2/3/4** (`src/fs/ext.c`) — ext2 leaves block pointers in the inode. ext3
and ext4 zero them, which is why the standard advice is to unmount immediately.
Two things still survive and are exploited: orphaned directory entries (unlink
only lengthens the preceding entry's `rec_len` to skip over the deleted one, so
the name and inode number stay readable in the gap), and inodes whose extent
tree or block map is intact. Recovered inode numbers are matched back to orphan
names so the carver has real filenames to attach.

### 6.2 Signature scanning

`src/carve/aho.c` builds an Aho–Corasick automaton over all enabled signature
headers. A naive carver runs one `memcmp` per signature per byte — with 54
signatures that is 54 comparisons for every byte of a multi-terabyte image. The
automaton matches all of them in one state transition per byte, so scan time is
independent of how many types are enabled. Signatures sharing a header prefix
(the two TIFF byte orders, GIF87a/89a) are chained through an output link so
none is missed.

### 6.3 Structure-aware extent resolution

This is the difference between a carver that produces usable files and one that
produces garbage. 24 of the 54 signatures carry a validator that reads the
file's own length information:

| Format | How the length is determined |
|---|---|
| JPEG | strict marker-segment walk to EOI |
| PNG | chunk walk to IEND, with CRC-32 verification of every chunk |
| GIF | block walk to the 0x3B trailer |
| BMP | `bfSize`, corroborated by nine other header fields |
| RIFF (WAV/AVI/WebP) | RIFF chunk size + form-type check |
| MP4/MOV/HEIC | ISO base-media box walk |
| ZIP (and docx/xlsx/pptx/apk) | End Of Central Directory, checked for self-consistency |
| PDF | first `%%EOF`, extended only across genuine incremental updates |
| SQLite | page size × page count |
| ELF / PE | section-header table end; PE also honours the Authenticode blob |
| 7z / CAB / EVTX / DEX | explicit length fields |
| TIFF | IFD walk to the furthest data extent |
| MP3 | frame walk (≥ 9 consecutive frames required) |
| Ogg | page walk to the end-of-stream page |
| ISO 9660 | volume space size from the primary volume descriptor |

Two validator design rules earned their place through testing:

**Reject, do not defer.** A validator that returns "unknown" makes the carver
widen its window. `MZ` is a two-byte magic that fires about a thousand times per
64 MiB of random data; a deferred answer for each cost a 48 MiB read. The PE
validator now rejects outright when `e_lfanew` is out of plausible range. That
one change took a scan of a sanitized 64 MiB image from 51 seconds to 6.6.

**Strictness enables reassembly.** The JPEG validator refuses to re-synchronise
on the next `0xFF`. A lenient walk would stride across a foreign cluster and
"find" an EOI belonging to a different file, producing a corrupt carve that
still looks valid. Failing instead hands the file to the gap carver, which is
where it can actually be reassembled correctly.

### 6.4 Bi-fragment gap carving

When the header is sound but the contiguous extent does not validate, the file
was probably split by the allocator. FORGE tries the classic two-fragment
model: keep the first fragment up to a cluster boundary, skip a gap that is a
whole number of clusters, splice, and ask the validator again. 24 × 24 candidate
reassemblies is enough for the common case of one intervening allocation, and
the search stops as soon as a validator parses cleanly.

This is tried **before** the footer search for structure-aware types, because a
footer hit on a fragmented file would "succeed" while silently including a
foreign cluster.

### 6.5 Progressive window reads

Resolving a hit reads a 64 KiB probe first. Most validators decide from that
alone. Only a hit that needs a wider view grows — first to 4 MiB, and to the
full 48 MiB ceiling only if the structure parsed far enough to look promising.
A magic number shorter than 4 bytes with no structural evidence never grows at
all.

### 6.6 Confidence scoring

`src/carve/classify.c` starts from the recovery method (metadata 70, structure
60, fragment 35, slack 25, bare signature 30) and adjusts for every independent
check that passed or failed: header validity, exact structural length, footer
presence, internal checksums (PNG chunk CRCs, ZIP CRCs), size sanity against the
format's bounds, entropy consistency, fragment count, and cluster reallocation
risk read from the filesystem's allocation bitmap.

The rule that matters most: **an extent with no parsed structure, no footer and
no checksum is capped at 25**, below the default reporting floor of 30. A magic
number on its own is not evidence. Every score ships with the reasoning string
that produced it, so a reviewer can audit the number instead of trusting it.

### 6.7 Evidential integrity

The source is opened read-only for the entire operation — the software
equivalent of a write blocker. Each recovered object is hashed with SHA-256 and
MD5 at extraction time (MD5 only because NSRL and HashKeeper hash sets still key
on it; it is never used for an integrity decision), and reported with the byte
offset it came from, so any later copy can be proven identical.

## 7. Reporting and audit

### 7.1 The hash chain

The audit log is newline-delimited JSON. Record *N* stores

```
hash_N = SHA-256( hash_{N-1} ‖ canonical_fields_N )
```

so altering, reordering or deleting any record invalidates every hash after it.
The canonical form is built separately from the rendered JSON, so whitespace or
key-order changes cannot alter what was signed, and it covers every attributable
field — sequence, timestamp, session, **operator**, **case**, event, status,
subject and detail. (Operator and case were added after testing showed that
editing the operator name alone left the chain valid: "who did this" is exactly
the field an attacker wants to change.)

### 7.2 The seal

At session end the log gets

```
HMAC-SHA256( session_key, hash_last )
```

An attacker who rewrites the whole file can recompute the chain, but not the
seal, without the key — which the operator archives separately.

A log file accumulates one independent chain per session, because sessions
append to the same file. `fg_audit_verify_file` therefore verifies per session
and reports the total across all of them.

### 7.3 Reports

Drive erasure, file erasure and recovery each render to HTML, JSON, CSV and
plain text. The HTML is fully self-contained — no external CSS, fonts or
scripts — with a print stylesheet, light and dark themes, and the audit chain
head printed on the certificate so it can be re-verified independently.

## 8. User interface

`forge serve` starts a dependency-free HTTP/1.1 server (`src/ui/httpd.c`) that
binds to loopback by default, requires a bearer token generated at startup, and
serves one page and a JSON API. The dashboard is compiled into the binary by
`tools/bin2c`, so the whole product remains a single executable.

Operations run on background threads through a job manager
(`src/ui/jobs.c`) with cooperative cancellation: the progress callback returns
non-zero and the engine unwinds at the next block boundary. Erasing a 2 TB drive
takes hours; the UI must stay responsive throughout.

A forensic workstation should not be running a general-purpose web server, so
the server speaks nothing beyond what the dashboard needs.

## 9. Testing

`forge selftest` runs 21 checks: SHA-256, HMAC-SHA256 and MD5 known-answer
vectors from FIPS 180-4, RFC 4231 and RFC 1321; the CRC-32 check value; CSPRNG
distinctness and entropy; pattern generation for DoD and Gutmann; the PNG, JPEG
and BMP validators; Aho–Corasick coverage; audit chain construction and
single-byte tamper detection; and a real end-to-end file erasure.

`ctest` additionally builds a synthetic evidence image and scores recovery
against planted digests. See `docs/VALIDATION.md` for methodology and results.

The whole suite runs clean under AddressSanitizer with leak detection — which is
how the thread use-after-free in `fg_thread_detach` was found.
