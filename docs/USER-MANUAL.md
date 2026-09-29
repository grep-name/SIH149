# FORGE — User Manual

Version 1.0.0 · SIH PS 26149 · NTRO

---

## Before you start

Raw device operations need **Administrator** on Windows or **root** on
Linux/macOS. Without elevation, `forge devices` shows nothing and every erase
or recovery against a physical device is refused with a clear message. Working
on image files needs no special privilege.

Check your build first:

```
forge selftest
```

21 checks, including known-answer tests for every cryptographic primitive the
certificates depend on. If this does not print `all checks passed`, do not trust
a certificate the binary produces.

---

## 1. Discovery

```
forge devices           # attached storage, with serial numbers and mount state
forge methods           # the 13 sanitization standards
forge types             # the 54 recoverable file signatures
forge parts --source <dev|image>    # partition table and filesystems
```

`forge devices` output:

```
DEVICE                   MODEL                      SERIAL             CAPACITY  TYPE           MOUNTED
/dev/sda                 Samsung SSD 980 PRO        S5GXNX0T512345     931.51 GiB SSD/NVMe      /,/boot  [SYSTEM DISK]
/dev/sdb                 SanDisk Cruzer Blade       4C530001120611     28.64 GiB  Flash/USB     -
```

Note the serial number — you will need it (or the word `ERASE`) to confirm a
wipe.

Add `--json` to any command for machine-readable output.

---

## 2. Module 1 — Secure Drive Eraser

```
forge erase drive --device <path> --confirm <serial|ERASE> [options]
```

| Option | Meaning |
|---|---|
| `--method <id>` | Sanitization standard. Default `nist-clear`. |
| `--verify <mode>` | `none`, `sample` (default), or `full`. |
| `--no-firmware` | Skip ATA/NVMe sanitize; overwrite only. |
| `--no-trim` | Do not issue TRIM after the passes. |
| `--allow-system-disk` | Permit a mounted or OS-bearing disk. **Dangerous.** |
| `--dry-run` | Report what would happen and stop. |
| `--report <file>` | Write a certificate. Format follows the extension: `.html`, `.json`, `.csv`, `.txt`. |
| `--case <id>` `--operator <name>` `--org <name>` | Recorded on the certificate and in the audit log. |

### Choosing a method

**On an SSD or NVMe drive, use `nist-purge`.** Host-level overwriting cannot
reach over-provisioned or remapped flash blocks; only the drive's own sanitize
command can. `nist-purge` issues that command and falls back to overwriting only
if the device refuses, recording on the certificate exactly which happened.

**On a magnetic hard drive, `nist-clear` is enough.** NIST SP 800-88 Rev.1 is
explicit that a single overwrite pass defeats all known recovery techniques on
modern drives. `dod3`, `vsitr`, `gutmann` and the rest are offered because
organisational policy and procurement contracts still name them — Gutmann's
35 passes were designed for MFM and RLL encodings that left the market in the
1990s.

**`crypto` only works on a self-encrypting drive.** It discards the media
encryption key, which makes every block unreadable instantly. If the device
does not support it, FORGE fails loudly rather than quietly doing something
weaker.

### Worked example

```
sudo forge erase drive \
     --device /dev/sdb \
     --method nist-purge \
     --verify full \
     --confirm 4C530001120611 \
     --case 2026-114 --operator "A. Investigator" --org "Cyber Cell" \
     --report /cases/2026-114/certificate.html
```

Output ends with a certificate summary:

```
Method         : NIST 800-88 Purge
Standard       : NIST SP 800-88 Rev.1, Purge
Passes         : 1 of 1 (firmware assisted)
Verification   : full read-back, 100.0000% coverage, 0 mismatching byte(s), entropy 7.997 b/B
Result         : PASS - sanitization complete
```

### Safety interlocks

FORGE refuses, in order, and each refusal is logged:

1. the disk holding the running operating system;
2. any disk with mounted volumes;
3. a missing or wrong `--confirm` token;
4. insufficient privileges.

`--allow-system-disk` overrides the first two. It exists because erasing a
decommissioned machine from a live boot stick is a real workflow, not because
it is safe.

### Reading the certificate

- **Unwritable sectors** are reported, never hidden. Sectors the drive has
  retired through its own defect management are not addressable by any host
  overwrite. For media leaving a controlled environment, a firmware Purge or
  physical destruction is the only complete option, and the certificate says so.
- **Coverage** tells you how much of the device verification actually examined.
  `sample` mode reads 4096 windows of 64 KiB; `full` reads everything.
- **Entropy** near 8.0 bits/byte after a random pass is what correct looks like.
  A lower figure means structured data survived.

---

## 3. Module 2 — Secure File and Folder Eraser

```
forge erase file <path> [path...] [options]
```

| Option | Meaning |
|---|---|
| `--method <id>` | Default `dod3`. |
| `--verify <mode>` | `none`, `sample` (default), `full`. |
| `--no-recurse` | Do not descend into subfolders. |
| `--no-metadata` | Keep names, timestamps, alternate data streams and xattrs. |
| `--no-slack` | Do not wipe cluster slack. |
| `--rmdir` | Remove directories left empty. |
| `--include <globs>` / `--exclude <globs>` | Comma-separated, e.g. `*.docx,*.pdf`. |
| `--dry-run` | List targets without touching them. |
| `--report <file>` | Per-file report. |

### What actually gets destroyed

Far more than the file content. For each target, in order: alternate data
streams and extended attributes; the data stream, flushed to the medium after
every pass; the cluster slack past end-of-file; the length, by staged
truncation; the filename, by renaming five times through shrinking random names;
the timestamps; and finally the directory entry.

That ordering is deliberate. Metadata goes first so that an interrupted
operation has at least destroyed the hidden copies.

### Example

```
sudo forge erase file /cases/2026-114/exports \
     --method dod3 --verify full --rmdir \
     --include "*.docx,*.pdf,*.xlsx" \
     --report /cases/2026-114/erasure.html
```

```
Files erased : 47 of 47  (0 failed)
Data erased  : 1.82 GiB
Slack wiped  : 96,412 bytes
ADS removed  : 3    xattrs removed: 12
Directories  : 4 removed
```

### Free-space wiping

```
forge erase freespace --volume <path> [--method <id>]
```

Everything deleted before FORGE was installed still sits in unallocated
clusters. This fills them, including the directory-entry and MFT-record space
that holds the names and resident content of small deleted files, then releases
everything.

It will temporarily consume nearly all free space on the volume, leaving a
32 MiB margin. Expect it to take as long as writing the whole free space once
per pass.

### If a file fails verification

The most common causes are copy-on-write filesystems (Btrfs, ZFS, APFS with
snapshots), compressed or encrypted NTFS attributes, and network shares. In all
of those the filesystem may write a *new* copy rather than overwriting in place,
which means the original blocks are untouched. FORGE reports this rather than
claiming success. On such volumes, wipe the free space afterwards — or sanitize
the whole device.

---

## 4. Module 3 — Advanced File Carving and Recovery

```
forge recover --source <dev|image> [options]
```

| Option | Meaning |
|---|---|
| `--out <dir>` | Where recovered files are written. Default `recovered`. |
| `--types <list>` | `jpg,pdf,docx,…` Default: every type. |
| `--categories <list>` | `image,document,archive,audio,video,executable,database,email,forensic-artifact,crypto-material,disk-image` |
| `--min-confidence <n>` | Discard results below n. Default 30. |
| `--no-metadata` | Skip filesystem parsing; carve only. |
| `--no-carve` | Filesystem metadata recovery only. |
| `--no-fragment` | Disable bi-fragment gap carving. |
| `--unallocated-only` | Ignore clusters that are currently allocated. |
| `--catalogue-only` | List what is there without extracting. |
| `--start <bytes>` `--end <bytes>` | Restrict the scanned range. |
| `--max <n>` | Stop after n files. |
| `--report <file>` | Forensic report. |

### Recommended workflow

**Image first.** Work from a forensic image, not the original device, whenever
you can. FORGE opens the source read-only and never writes to it, but working
from an image means the original is untouched by anything at all.

**Start with a catalogue.**

```
sudo forge recover --source /dev/sdc --catalogue-only \
     --report /cases/2026-114/survey.html
```

This tells you what filesystem is there, how much is recoverable and at what
confidence, without writing gigabytes to disk.

**Then extract what you need.**

```
sudo forge recover --source /dev/sdc \
     --out /cases/2026-114/recovered \
     --types jpg,png,pdf,docx,xlsx,sqlite,eml \
     --min-confidence 50 \
     --case 2026-114 --operator "A. Investigator" \
     --report /cases/2026-114/findings.html
```

### Reading confidence scores

| Range | What it means |
|---|---|
| **75–100** | Structure parsed to an exact length, or recovered from intact filesystem metadata, usually with checksums verified. Treat as reliable. |
| **45–74** | Header and footer agree but the internal structure did not fully parse. Usually a genuine but damaged or partially overwritten file. Worth examining. |
| **25–44** | A header match with no corroboration. May be a chance byte sequence. Examine before relying on it. |
| **≤ 25** | Capped: no structure, no footer, no checksum. Reported only if you lower `--min-confidence`. |

Every score carries the reasoning that produced it. In the HTML report, hover a
confidence badge; in JSON it is the `confidence_basis` field. Audit the number
rather than trusting it.

### Recovery methods in the report

- **filesystem metadata** — the strongest. The original name, path, timestamps
  and fragmentation came from `$MFT`, a FAT directory entry, an exFAT entry set
  or an ext inode. On NTFS, small files stored resident in the MFT record
  survive a delete completely intact.
- **structure-based carving** — the file's own length fields gave an exact
  extent.
- **fragment reassembly** — the file was split by the allocator and was
  reassembled by testing candidate gap sizes until the format validated.
- **signature carving** — header to footer, no structural confirmation. The
  weakest, scored accordingly.

Names beginning with `_` come from FAT: deleting a file overwrites the first
character of its name with `0xE5`, so that character is genuinely gone and
FORGE substitutes an underscore rather than inventing one.

### When ext4 recovers little

ext3 and ext4 zero an inode's block pointers on delete. FORGE exploits what
survives — orphaned directory entries, intact extent trees — but the content of
most deleted ext4 files has to come from carving. That is a property of the
filesystem. The single most effective thing you can do is unmount the volume
immediately, before the blocks are reused.

---

## 5. Audit and reporting

Every erase and recovery session appends to an audit log (`forge-audit.log` by
default, `--audit-log` to change it). Record *n* stores the SHA-256 of the
previous hash concatenated with record *n*, so altering, reordering or removing
any record breaks every hash after it. At session end the chain is sealed with
HMAC-SHA256.

### Sealing with your own key

```
forge recover --source /dev/sdc --audit-key <64 hex chars> ...
```

Archive that key separately from the log. Without it, an attacker who rewrites
the file can recompute the chain; with it, they cannot forge the seal.

### Verifying

```
forge audit verify --log forge-audit.log --key <hex>
```

```
Audit log : forge-audit.log
  records   : 8 in 2 session(s)
  chain     : INTACT
  HMAC seal : VERIFIED
  head      : c1b92c8477970238a52fbcae010e5be0102ad1a766bdc60396c176de138f69fd
  verdict   : hash chain intact across 8 record(s) in 2 session(s); all HMAC seals verified
```

A broken chain names the first bad record. Exit status is non-zero, so this
works in a pipeline.

### Report formats

`--report` picks the format from the extension:

- **`.html`** — self-contained, print-ready certificate or forensic report. No
  external assets, works offline forever.
- **`.json`** — the complete structured record, for case-management systems.
- **`.csv`** — one row per file, for spreadsheets.
- **`.txt`** — plain text summary.

---

## 6. The dashboard

```
sudo forge serve [--port 8787] [--bind 127.0.0.1] [--token <hex>]
```

```
  Dashboard : http://127.0.0.1:8787/?token=a3f1…
  API token : a3f1…
  Privileges: elevated
```

Open the printed URL. Five tabs: Drive Eraser, File & Folder Eraser, Recovery &
Carving, Jobs & Reports, Audit.

The server binds to loopback by default and requires the token on every API
call. It is a tool console, not a web application — do not expose it. If you
must bind elsewhere, `--bind` exists, and you should put it behind something
that does TLS and authentication properly.

Operations run in the background with live progress and a cancel button; a 2 TB
wipe takes hours and the UI stays responsive. Finished jobs offer their report
in HTML, JSON and CSV.

### API

All endpoints need `X-Forge-Token` (or `?token=`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/system` | Version, host, privileges, audit session state |
| GET | `/api/devices` | Attached storage |
| GET | `/api/methods` | Sanitization standards |
| GET | `/api/signatures` | Recoverable file types |
| POST | `/api/erase/drive` | Start a drive wipe |
| POST | `/api/erase/files` | Start a file/folder wipe |
| POST | `/api/erase/freespace` | Start a free-space wipe |
| POST | `/api/recover` | Start a recovery scan |
| GET | `/api/jobs` · `/api/jobs/<id>` | Job state and results |
| POST | `/api/jobs/<id>/cancel` | Cancel |
| GET | `/api/jobs/<id>/report?format=html\|json\|csv\|text` | Report |
| POST | `/api/audit/verify` | Verify a log |

```bash
curl -H "X-Forge-Token: $TOKEN" -X POST \
     -d '{"source":"/dev/sdc","out_dir":"/cases/rec","min_confidence":50}' \
     http://127.0.0.1:8787/api/recover
```

---

## 7. Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | The operation ran but failed (verification failed, chain broken, artefacts missing) |
| 2 | Usage error — bad arguments |

---

## 8. Troubleshooting

**`forge devices` lists nothing.** Not elevated. Use `sudo`, or on Windows run
the terminal as Administrator.

**"refusing to erase … volumes are still mounted".** Unmount them.
`--allow-system-disk` overrides, but read section 2 first.

**"confirmation token does not match".** `--confirm` must be the device's serial
number exactly as `forge devices` prints it, or the literal word `ERASE`.

**Firmware sanitize refused, "FROZEN security state".** The BIOS froze the ATA
security feature set at boot. A suspend/resume cycle usually thaws it; otherwise
use an overwrite method.

**Recovery finds nothing on a device with data on it.** The filesystem may be
encrypted (BitLocker, FileVault, LUKS). Carving encrypted volumes returns
nothing by design — unlock first, then image the unlocked volume.

**Recovery is slow on a device full of random-looking data.** Expected. Encrypted
or fully-random media produces chance header matches; FORGE probes each one
cheaply and rejects it, but there are many. Narrow with `--types` or
`--unallocated-only`.
