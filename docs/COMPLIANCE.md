# FORGE — Standards Compliance Matrix

Version 1.0.0 · SIH PS 26149 · NTRO

This document states precisely what FORGE implements from each standard, and
what it does not.

---

## 1. Data sanitization standards

### NIST SP 800-88 Rev.1 — *Guidelines for Media Sanitization*

The reference framework, and the one whose categories FORGE's reports use.

| Category | Implemented as | Notes |
|---|---|---|
| **Clear** | `--method nist-clear` (one pseudorandom pass + verification) or `zero` / `random` | Defeats all keyboard and software recovery. On modern magnetic media NIST states one pass is sufficient. |
| **Purge** | `--method nist-purge` | Attempts ATA SANITIZE, ATA SECURITY ERASE UNIT, NVMe Sanitize or NVMe Format NVM first; falls back to an overwrite pass with verification if the device refuses, and records which happened on the certificate. |
| **Purge — Cryptographic Erase** | `--method crypto` | NVMe Sanitize (crypto scramble), NVMe Format with SES=2, or ATA SANITIZE CRYPTO SCRAMBLE. Fails loudly rather than silently degrading if unsupported. |
| **Destroy** | not applicable | Physical destruction. FORGE's certificates say so where it is the only complete option. |
| **Verification** | `--verify sample` / `--verify full` | §4.8 of the standard requires verification. Sampled mode reads 4096 windows of 64 KiB; full mode reads every sector. Coverage, mismatch count, entropy and a SHA-256 over what was examined all appear on the certificate. |
| **Documentation** | HTML / JSON / CSV / text certificates | Appendix G lists the fields a certificate should carry; §4 below maps them. |

### Overwrite patterns

| Standard | `--method` | Passes | Pattern |
|---|---|---:|---|
| US DoD 5220.22-M (NISPOM 8-306) | `dod3` | 3 | `0x00`, complement, random + verify |
| US DoD 5220.22-M ECE | `dod7` | 7 | the 3-pass sequence, a random pass, the 3-pass sequence again |
| German BSI-VSITR | `vsitr` | 7 | `0x00`/`0xFF` alternating three times, then `0xAA` |
| UK HMG Infosec Standard 5, Enhanced | `hmg` | 3 | `0x00`, `0xFF`, random + verify |
| GOST R 50739-95 (Russia) | `gost` | 2 | `0x00`, random + verify |
| Schneier, *Applied Cryptography* 2e | `schneier` | 7 | `0x00`, `0xFF`, five random |
| Gutmann 1996 | `gutmann` | 35 | 4 random, 27 targeted MFM/RLL patterns, 4 random |

**A necessary caveat.** DoD 5220.22-M was withdrawn as a sanitization
specification; NISPOM now refers to the DSS/DCSA clearing and sanitization
matrix. Gutmann's 35 passes were designed for MFM and RLL encodings that left
the market in the 1990s; Gutmann himself has written that on modern drives a few
random passes are all that is meaningful. FORGE implements these because
organisational policy, audit checklists and procurement contracts still name
them, not because they are more effective than `nist-clear` on current media.

### IEEE 2883-2022 — *Standard for Sanitizing Storage*

Not claimed as a compliance target. FORGE's Clear / Purge / verification model
aligns with its structure, and the firmware sanitize paths are those IEEE 2883
prefers for flash media, but no conformance testing against the standard has
been performed.

---

## 2. Forensic standards and practice

| Requirement | Source | How FORGE addresses it |
|---|---|---|
| Evidence must not be altered | ACPO Principle 1; ISO/IEC 27037 §7 | The source is opened **read-only** for the entire operation. No write is ever issued to evidence media — the software equivalent of a write blocker. |
| The examiner must be competent to explain their actions | ACPO Principle 2 | Every algorithm is documented in `docs/TECHNICAL.md`, and each confidence score ships with the reasoning string that produced it. |
| An audit trail must exist and be reproducible by a third party | ACPO Principle 3 | Hash-chained, HMAC-sealed audit log; `forge audit verify` re-walks it independently. |
| Integrity of acquired data must be demonstrable | ISO/IEC 27037 §7.1.3 | SHA-256 and MD5 computed at extraction time for every recovered object, with its source byte offset. |
| Chain of custody | ISO/IEC 27037 §7.1.4 | Case ID, operator, organisation, workstation, OS, timestamps and the audit chain head are recorded on every report. |
| Tool results must be verifiable | NIST CFTT methodology | `forge selftest` runs published test vectors; `ctest` scores recovery against a manifest of known digests. See `docs/VALIDATION.md`. |

MD5 is computed **only** because NSRL and HashKeeper hash sets still key on it.
It is never used for an integrity decision inside FORGE.

---

## 3. Cryptographic primitives

| Primitive | Specification | Verified against |
|---|---|---|
| SHA-256 | FIPS 180-4 | FIPS 180-4 test vectors, in `selftest` |
| HMAC-SHA256 | RFC 2104 / FIPS 198-1 | RFC 4231 test case 2, in `selftest` |
| MD5 | RFC 1321 | RFC 1321 test vector, in `selftest` |
| ChaCha20 | RFC 8439 | Used as a keystream generator for overwrite patterns |
| CRC-32 | ISO 3309 / ITU-T V.42 | Published check value `0xCBF43926`, in `selftest` |

Implementations are in-tree and independently auditable. **They are not
FIPS 140-validated**, and FORGE does not claim a FIPS 140 module boundary.
Where a validated module is a procurement requirement, that requirement is not
met by this implementation.

---

## 4. Certificate of sanitization — field coverage

NIST SP 800-88 Rev.1 Appendix G lists what a sanitization record should carry.

| Appendix G field | On the FORGE certificate |
|---|---|
| Manufacturer / model | `model` (from the storage property query) |
| Serial number | `serial` |
| Media type | HDD / SSD / Flash / Optical, plus bus type |
| Media source | Case ID and organisation |
| Sanitization method | Method name and the standard it implements |
| Tool used, including version | `FORGE 1.0.0` |
| Verification method | Full or sampled, with byte count, coverage %, mismatch count, entropy and a SHA-256 over the verified sample |
| Verified by | Operator name |
| Date | ISO 8601 UTC start and finish timestamps |
| Backup | Out of scope — an operational control, not a tool function |

Additional fields FORGE records beyond Appendix G: report ID, capacity and
sector size, passes completed versus planned, bytes written, unwritable sector
count and first bad offset, elapsed time and throughput, whether firmware
sanitize was used and what it reported, and the audit chain head hash.

---

## 5. Filesystem and format support

### Metadata-based recovery

| Filesystem | Support | Basis |
|---|---|---|
| NTFS | Full | `$MFT` record walk with update-sequence fixups, run-list decoding, resident data, `$FILE_NAME` namespace selection, `$Bitmap` for allocation state |
| FAT12 / FAT16 / FAT32 | Full | `0xE5` directory entries, long-filename reassembly, FAT-based allocation map. Contiguity is assumed because the chain is released on delete; reflected in the confidence score |
| exFAT | Full | `0x05`/`0x85` entry sets with stream-extension and name entries; the no-FAT-chain flag states contiguity outright |
| ext2 | Full | Inode block maps survive deletion |
| ext3 / ext4 | Partial | Block pointers are zeroed on delete. Orphaned directory entries and intact extent trees are exploited; the rest falls to carving. A filesystem property, not a tool limitation |
| HFS+, APFS, XFS, Btrfs | Detected only | Identified and reported; recovery is carving-only |

### Partition schemes

MBR (including extended/logical partition chains) and GPT.

### Carving signatures

54 signatures across 11 categories. **24 carry a structural validator** that
resolves the exact file length from the format's own headers rather than
guessing from a footer — `forge types` marks these, and they are what produce
the high-confidence results.

Images: JPEG, PNG, GIF (87a/89a), BMP, TIFF (both byte orders), WebP, PSD, ICO,
HEIF/HEIC.
Documents: PDF, RTF, OLE compound (doc/xls/ppt/msg), XML, HTML.
Archives & OOXML: ZIP (docx/xlsx/pptx/jar/apk), RAR 4 and 5, 7-Zip, gzip,
bzip2, XZ, Microsoft Cabinet.
Audio: MP3 (ID3v2 and raw frame), WAV, FLAC, Ogg, MIDI.
Video: MP4/MOV/3GP, Matroska/WebM, FLV, ASF/WMV.
Executables: PE, ELF, Mach-O, DEX, Java class, shell scripts.
Databases & artefacts: SQLite, Windows Event Log, Outlook PST, registry hives,
LNK shortcuts, pcap, pcapng.
Email: RFC 822 messages.
Crypto material: PEM, DER/PKCS#12.
Disk images: ISO 9660, VHD, VMDK, QCOW2.

---

## 6. Platform support

| | Windows | Linux | macOS |
|---|---|---|---|
| Device enumeration | SetupDi / `IOCTL_STORAGE_QUERY_PROPERTY` | `/sys/block` | `sys/disk.h` ioctls |
| Raw read/write | `CreateFileW` + `FILE_FLAG_NO_BUFFERING` | `O_DIRECT` | `F_NOCACHE` |
| Volume dismount | `FSCTL_LOCK_VOLUME` / `FSCTL_DISMOUNT_VOLUME` | `BLKRRPART` | — |
| ATA firmware sanitize | `IOCTL_ATA_PASS_THROUGH` | `SG_IO` ATA-16 | **not available** |
| NVMe sanitize / format | vendor-specific, best effort | `NVME_IOCTL_ADMIN_CMD` | **not available** |
| Secure TRIM | not exposed for whole devices | `BLKSECDISCARD` / `BLKDISCARD` | — |
| Alternate data streams | `FindFirstStreamW` | n/a | n/a |
| Extended attributes | n/a | `llistxattr` / `lremovexattr` | `listxattr` with `XATTR_NOFOLLOW` |

macOS exposes no ATA/NVMe pass-through to userspace without a kernel extension.
On that platform `nist-purge` falls back to overwriting and states this on the
certificate; `crypto` reports that it is unavailable rather than doing something
weaker.

---

## 7. What FORGE does not and cannot do

Stated explicitly, because these limits are physical and no tool overcomes them:

1. **Host-level overwriting cannot reach retired sectors.** Blocks the drive has
   remapped through its own defect management are not addressable by any write
   from the host. FORGE counts and reports them; it does not pretend they were
   erased.

2. **Host-level overwriting cannot reach SSD over-provisioning.** A flash
   translation layer keeps spare blocks the host never addresses, which may hold
   previous copies of user data. Only a firmware Purge reaches them. This is why
   `nist-purge` is the correct choice on solid-state media and why a certificate
   that used the overwrite fallback says so.

3. **Cryptographic erase is only as strong as the drive's implementation.** It
   discards the media encryption key. If the drive's key management is flawed,
   so is the erase. FORGE cannot audit a drive's firmware.

4. **Recovery cannot resurrect overwritten data.** Once clusters have been
   reallocated and rewritten, the content is gone. FORGE reports a
   reallocation-risk figure from the filesystem's allocation bitmap rather than
   implying otherwise.

5. **Encrypted volumes yield nothing to carving.** BitLocker, FileVault and LUKS
   volumes must be unlocked before imaging. This is by design and applies to
   every forensic tool.

6. **Copy-on-write filesystems may defeat in-place file erasure.** On Btrfs,
   ZFS or APFS with snapshots, the filesystem may write a new copy rather than
   overwriting in place. FORGE's verification detects this and reports it
   rather than claiming success; the correct remedy is a free-space wipe or
   whole-device sanitization.
