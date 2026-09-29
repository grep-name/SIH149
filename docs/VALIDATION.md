# FORGE — Validation & Testing Report

Version 1.0.0 · SIH PS 26149 · NTRO

All figures in this document were measured on the build in this repository.
Every test is reproducible with `cmake --build build && cd build && ctest`.

---

## 1. Test environment

| | |
|---|---|
| Platform | Linux x86-64, ext4 |
| Compiler | GCC, C11, `-O2 -Wall -Wextra -Wshadow` |
| Build warnings | **0** on a clean build |
| Source size | ~13,000 lines of C across 37 files |
| External dependencies | none |
| Memory checking | AddressSanitizer with `detect_leaks=1` across every code path |

---

## 2. Unit and known-answer tests — `forge selftest`

26 checks, all passing.

### 2.1 Cryptographic primitives

The certificates FORGE issues are only as trustworthy as the hashes behind
them, so every primitive is checked against its published test vector.

| Check | Vector |
|---|---|
| SHA-256 of `"abc"` | FIPS 180-4 |
| SHA-256 of the empty string | FIPS 180-4 |
| HMAC-SHA256, key `"Jefe"` | RFC 4231 test case 2 |
| MD5 of `"abc"` | RFC 1321 |
| CRC-32 of `"123456789"` → `0xCBF43926` | published check value |

### 2.2 CSPRNG

| Check | Result |
|---|---|
| Two 4 KiB blocks differ | pass |
| Entropy of a 4 KiB block | > 7.5 bits/byte |

### 2.3 Pattern engine

| Check | Result |
|---|---|
| DoD pass 1 writes `0x00` | pass |
| DoD pass 2 writes the complement `0xFF` | pass |
| Gutmann declares 35 passes | pass |
| CLI method-name parsing | pass |

### 2.4 Structure validators

| Check | Result |
|---|---|
| PNG validator returns the exact file length | pass |
| PNG chunk CRC-32s verify (quality 3) | pass |
| JPEG validator walks marker segments to EOI | pass |
| BMP validator reads `bfSize` and corroborating fields | pass |
| Aho–Corasick finds all four planted signatures | pass |

### 2.5 Audit chain

| Check | Result |
|---|---|
| A five-record chain verifies, and its HMAC seal matches | pass |
| Flipping **one byte** inside one record breaks the chain | pass |

### 2.6 Unbuffered I/O alignment

These exist because of a real bug found during testing (§6.1).

| Check | Result |
|---|---|
| Aligned allocator returns block-aligned memory | pass |
| Drive eraser completes against an image opened `O_DIRECT` | pass |
| All three DoD passes were actually written | pass |
| No spurious "unwritable sector" reports | pass |
| Full read-back verification at 100 % coverage | pass |
| No plaintext survives the overwrite | pass |

### 2.7 File eraser

| Check | Result |
|---|---|
| Target file erased | pass |
| Overwrite verified before unlink | pass |
| Target no longer exists | pass |

---

## 3. End-to-end recovery — methodology

`forge_mkimage` builds a synthetic evidence image with a **real MBR and a real
FAT32 volume** — boot sector, two FAT copies, cluster chains and directory
entries all constructed byte by byte, not simulated. Into it it plants:

| Class | What it is | What must happen |
|---|---|---|
| **live** | Files with intact directory entries and FAT chains | Not a recovery target |
| **deleted** | Directory entry stamped `0xE5` and the FAT chain released — exactly what a real delete does | Must be recovered *by name* through metadata parsing |
| **orphan** | File bodies written into unallocated clusters with no directory entry at all | Only carving can find these |
| **fragmented** | A JPEG split across two cluster ranges with a foreign cluster wedged between them | Only gap carving can reassemble this |

The gap cluster is filled with pseudo-random bytes rather than a constant,
because real intervening data contains `0xFF` bytes that desynchronise a JPEG
marker walk — filling it with a constant would be an unrealistically easy test.

Every planted artefact's SHA-256 is written to a manifest. `forge_score`
compares that manifest against the recovery report's digests, so a file counts
as recovered only if it came back **byte-for-byte identical**. Nothing is judged
by eye.

---

## 4. End-to-end recovery — results

64 MiB image, 14 planted artefacts, default settings
(`--min-confidence 30`, metadata + carving + gap carving all enabled).

```
  ARTEFACT       PLANTED AS       SIZE  RESULT   RECOVERY METHOD          RECOVERED AS
  ---------------------------------------------------------------------------------------
  live.pdf       live              434  (live)   structure-based carving  00000008_…pdf
  live.png       live              106  (live)   structure-based carving  00000009_…png
  secret.pdf     deleted           438  PASS     filesystem metadata      _ECRET.PDF
  evidence.png   deleted           117  PASS     filesystem metadata      _VIDENCE.PNG
  badge.gif      deleted            35  PASS     filesystem metadata      _ADGE.GIF
  ledger.zip     deleted           164  PASS     filesystem metadata      _EDGER.ZIP
  photo.jpg      deleted          9032  PASS     filesystem metadata      _HOTO.JPG
  chat.db        deleted          8192  PASS     filesystem metadata      _HAT.DB
  memo.pdf       deleted            81  PASS     filesystem metadata      _EMO.PDF
  orphan.pdf     orphan            433  PASS     structure-based carving  00000010_…pdf
  orphan.png     orphan            125  PASS     structure-based carving  00000011_…png
  orphan.zip     orphan            141  PASS     structure-based carving  00000012_…zip
  orphan.gif     orphan             35  PASS     structure-based carving  00000013_…gif
  split.jpg      fragmented      12032  PASS     fragment reassembly      00000014_…jpg

  Target artefacts       : 12
  Recovered byte-exact   : 12
  Recovery rate          : 100.0%
```

**12 of 12, byte-for-byte.** Specifically:

- all 7 deleted files recovered through FAT32 metadata **with their original
  filenames** (the leading `_` replaces the character FAT overwrote with
  `0xE5`, which is genuinely unrecoverable);
- all 4 orphaned bodies carved with exact extents from their own structure;
- the fragmented JPEG **reassembled across the gap**, SHA-256 matching the
  original exactly.

The two live files are also carved. That is correct: content carving cannot
distinguish allocated from unallocated data unless the allocation bitmap is
read, which is what `--unallocated-only` is for.

---

## 5. False positives

The hardest test for a carver is media with **no files on it at all**. A 64 MiB
image was sanitized with DoD 5220.22-M (final pass random), then scanned.

| Metric | Result |
|---|---|
| Candidate signature hits | 4,007 |
| Reported at default threshold (≥ 30) | **3** |
| Reported at ≥ 75 confidence | **0** |
| Highest confidence of any false positive | **53 %** |

4,007 chance hits in 64 MiB is expected: a 2-byte magic number occurs about
once every 65,536 random bytes. What matters is how many survive. The three that
do are JPEG header/footer pairs occurring by chance; each is scored 53 % with
the reasoning string `no corroborating structure, footer or checksum` visible in
the report, which is exactly what a 3-byte magic number plus a 2-byte footer
deserves.

This is the measurement that drove the confidence model: an extent with no
parsed structure, no footer and no checksum is capped at 25, below the default
reporting floor.

---

## 6. Defects found during validation

Each of these is now covered by a permanent regression test.

### 6.1 Unbuffered I/O alignment (critical)

`O_DIRECT` and `FILE_FLAG_NO_BUFFERING` require the buffer, length and offset to
be block-aligned. `malloc` returns 16-byte alignment, so **every write during a
drive wipe failed with `EINVAL`**, the failures were counted as bad sectors, and
the tool reported a healthy drive as "failing" after 32 MiB. It went unnoticed
initially because the AddressSanitizer build's allocator happens to return
aligned pointers.

*Fixed:* `fg_aligned_alloc` on both platforms, used on the eraser's hot path,
plus a read-modify-write bounce buffer in the platform layer so the API is
correct regardless of what a caller passes. Six self-test checks now cover it.

### 6.2 Thread use-after-free (crash)

`fg_thread_detach` freed the thread handle while the new thread was still
reading its entry-point arguments from it. The dashboard segfaulted on its
first HTTP request. Found by AddressSanitizer.

*Fixed:* entry arguments now live in their own allocation owned by the new
thread. Both `posix.c` and `win32.c`.

### 6.3 Small files always failed erasure verification

A random final pass was verified by entropy alone. Eleven random bytes cannot
carry more than log₂(11) ≈ 3.46 bits per byte, so **every file under ~4 KiB was
reported as unverifiable**.

*Fixed:* a random pass is now verified by comparing a digest of the sampled
regions taken before and after the overwrite (proof that something was
written), with the entropy test applied only when the sample is at least 4 KiB.

### 6.4 Attribution fields were outside the hash chain

Editing the `operator` field of an audit record left the chain verifying —
"who did this" is exactly the field an attacker wants to change.

*Fixed:* session id, operator and case id are now part of the canonical hashed
form. Verified by tampering: the chain reports `BROKEN` at the altered record.

### 6.5 Multi-session audit logs were misread

A log file accumulates one chain per session. The verifier treated the whole
file as a single chain and reported a correct two-session log as tampered.

*Fixed:* per-session chain verification; the verifier now reports "8 records in
2 sessions" and checks each session's seal independently.

### 6.6 PDF over-carving

`v_pdf` took the *last* `%%EOF` in the read window, which swallowed every PDF
that happened to follow on the media — a 433-byte document was carved as 56 KiB.

*Fixed:* the first `%%EOF` ends the file unless what follows is a genuine
incremental update (an object definition plus a `startxref`).

### 6.7 Lenient JPEG walk defeated gap carving

The JPEG validator re-synchronised on the next `0xFF`, so a fragmented file
"validated" while silently including a foreign cluster: 12,032 bytes carved as
16,128, with a wrong digest.

*Fixed:* the validator now fails on desynchronisation, which hands the file to
the gap carver — which reassembles it correctly.

### 6.8 Directory removal ordering

`--rmdir` removed nothing, because the root directory was attempted before its
children.

*Fixed:* directories are removed in descending path-length order.

### 6.9 Scan performance on high-entropy media

A scan of a sanitized 64 MiB image took **51 seconds**. Two causes: the PE
validator returned "unknown" for random data, forcing a 48 MiB read for each of
~1,000 chance `MZ` hits; and the MP3 frame walk ran to completion on each of
~128 chance `0xFF 0xFB` hits.

*Fixed:* validators reject decisively rather than deferring; a 64 KiB probe is
read before any large window; growth is staged (4 MiB, then the full ceiling
only for structurally promising hits) and is skipped entirely for magic numbers
shorter than 4 bytes with no evidence behind them.

**Result: 51 s → 6.6 s**, an 7.7× improvement, with false positives falling from
42 to 3 in the same change set.

---

## 7. Performance

256 MiB image, single-threaded, warm page cache. Throughput on real hardware is
bounded by the device, not by FORGE.

### 7.1 Sanitization

| Method | Passes | Data written | Time | Rate |
|---|---:|---:|---:|---:|
| `zero` | 1 | 256 MiB | 0.38 s | 679 MiB/s |
| `random` | 1 | 256 MiB | 1.17 s | 220 MiB/s |
| `dod3` | 3 | 768 MiB | 1.77 s | 434 MiB/s |
| `dod7` | 7 | 1.75 GiB | 5.00 s | 359 MiB/s |
| `gutmann` | 35 | 8.75 GiB | 27.17 s | 330 MiB/s |

The random-pass rate (220 MiB/s) is the ChaCha20 keystream generation cost. It
is far above any mechanical drive and comfortably above most SATA SSDs, so in
practice the device is always the bottleneck.

### 7.2 Verification

256 MiB, single zero pass:

| Mode | Time | Coverage |
|---|---:|---:|
| `none` | 0.52 s | 0 % |
| `sample` | 1.03 s | 25 % |
| `full` | 2.46 s | 100 % |

Sampled verification reads 4096 random 64 KiB windows, capped so it never
examines more than a quarter of the device — on a small volume, uncapped
sampling costs more than a sequential read-back and delivers less.

### 7.3 Recovery

| Source | Time | Rate |
|---|---:|---:|
| 256 MiB FAT32 image with real files | 1.46 s | 175 MiB/s |
| 64 MiB sanitized image (worst case: pure random data) | 6.6 s | 10 MiB/s |

The second figure is the pathological case by construction. Random data
maximises chance signature hits, each of which must be probed and rejected.
Real media is far closer to the first figure.

---

## 8. Memory safety

Every path was exercised under AddressSanitizer with leak detection:

| Path | Result |
|---|---|
| `selftest` | clean |
| Recovery, all strategies enabled | clean |
| Recovery, `--unallocated-only --catalogue-only` | clean |
| File erasure, Gutmann 35-pass, full verify, `--rmdir` | clean |
| Partition table parsing | clean |
| Audit verification | clean |
| Drive erasure with full read-back | clean |
| HTTP server: page, auth, all API endpoints, background job, report download | clean |

No leaks, no invalid accesses. §6.2 was found this way.

---

## 9. Automated regression suite

`ctest` runs six tests in under a second:

| # | Test | What it proves |
|---|---|---|
| 1 | `selftest` | 26 unit and known-answer checks |
| 2 | `build_image` | The synthetic evidence image builds |
| 3 | `clean_audit` | Fresh audit log for a deterministic run |
| 4 | `recover_image` | Recovery completes and emits a JSON report |
| 5 | `score_recovery` | **Non-zero exit if any planted artefact is not recovered byte-exact** |
| 6 | `verify_audit` | The audit chain written during the run verifies |

Test 5 is the one that matters: it fails the build if the recovery rate drops
below 100 % on the reference image.

---

## 10. Coverage limitations

Stated plainly, because a validation report that only lists successes is not
a validation report.

- **Firmware sanitize paths are not exercised in CI.** ATA SECURITY ERASE and
  NVMe Sanitize are destructive operations against real hardware; there is no
  way to test them against an image. The code paths are implemented and the
  fallback behaviour when a device refuses is tested, but the commands
  themselves need manual validation on disposable media.
- **NTFS, exFAT and ext recovery are implemented but the automated suite only
  builds a FAT32 reference image.** The parsers were developed against the
  on-disk format specifications and manual testing; a fuller suite would build
  reference images for each filesystem.
- **macOS device enumeration** uses `sys/disk.h` ioctls rather than IOKit, so
  model and serial strings are less detailed than on Windows and Linux.
- **The 100 % recovery rate is against a reference image**, not a claim about
  arbitrary real-world media. Real recovery rates depend on how much has been
  overwritten since deletion, which no tool can change.
