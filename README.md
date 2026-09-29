# FORGE

**Integrated Secure Data Erasure & Forensic Recovery Platform**

Smart India Hackathon — Problem Statement **26149**
National Technical Research Organisation (NTRO) · Blockchain & Cybersecurity

---

Investigators today keep two toolboxes: one to destroy data beyond recovery, one
to recover data someone else tried to destroy. They rarely share a report
format, an audit trail, or a device abstraction. FORGE is a single C program
that does both, on Windows, Linux and macOS, with one evidence model and one
tamper-evident log.

```
┌──────────────────────── FORGE ─────────────────────────┐
│  Module 1        Module 2           Module 3           │
│  Drive Eraser    File/Folder        Carving &          │
│                  Eraser             Recovery           │
│  ├ 13 standards  ├ in-place wipe    ├ 54 signatures    │
│  ├ ATA/NVMe      ├ metadata scrub   ├ 24 validators    │
│  │  firmware     ├ ADS + xattrs     ├ NTFS/FAT/exFAT   │
│  │  sanitize     ├ cluster slack    │  /ext metadata   │
│  └ verification  └ free-space wipe  └ gap carving      │
├────────────────────────────────────────────────────────┤
│  Reporting & Audit  ·  hash-chained log, HMAC seal,    │
│                        HTML / JSON / CSV / text        │
├────────────────────────────────────────────────────────┤
│  CLI  ·  Web dashboard (embedded HTTP server)          │
└────────────────────────────────────────────────────────┘
```

Zero third-party dependencies. SHA-256, MD5, HMAC, ChaCha20, the JSON parser
and the HTTP server are all in-tree, so the binary runs from a forensic boot
stick with no package manager in sight.

---

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Windows needs MinGW-w64 (MSYS2: `pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake`):

```bat
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The build produces `forge` (the whole tool), plus `forge_mkimage` and
`forge_score` for validation.

## Prove it works

```bash
build/forge selftest          # 21 known-answer and behavioural checks
cd build && ctest              # end-to-end: plant artefacts, recover, score
```

`ctest` builds a synthetic 64 MiB evidence image containing live files, deleted
files, orphaned file bodies and one deliberately fragmented JPEG, recovers from
it, and scores the run against the planted SHA-256 digests. Current result:
**12 of 12 target artefacts recovered byte-for-byte.**

## Use it

```bash
sudo forge devices                      # what is attached

# Module 1 — sanitize a drive
sudo forge erase drive --device /dev/sdb --method nist-purge \
     --verify full --confirm ERASE --report certificate.html

# Module 2 — destroy selected files, and the traces they leave behind
sudo forge erase file ./case-exports --method dod3 --verify full --rmdir
sudo forge erase freespace --volume /home

# Module 3 — recover from a seized device or image
sudo forge recover --source /dev/sdc --out ./recovered \
     --case 2026-114 --operator "A. Investigator" --report findings.html

# Audit
forge audit verify --log forge-audit.log --key <hex>

# Dashboard
sudo forge serve          # then open the printed URL
```

Every command accepts `--json` for scripting.

## Documentation

| Document | What it covers |
|---|---|
| [`docs/USER-MANUAL.md`](docs/USER-MANUAL.md) | Every command and option, worked examples, the dashboard |
| [`docs/TECHNICAL.md`](docs/TECHNICAL.md) | Architecture, algorithms, the confidence model, on-disk parsing |
| [`docs/VALIDATION.md`](docs/VALIDATION.md) | Test methodology, measured results, false-positive rate, performance |
| [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) | Standards matrix and what each claim does and does not mean |

## Safety

Drive erasure refuses to run against the disk holding the running operating
system, refuses a disk with mounted volumes, and requires the operator to type
the device serial number (or the literal word `ERASE`) as confirmation. All
three interlocks are overridable, deliberately awkwardly.

The recovery path opens evidence read-only for the entire operation and never
issues a write to it.

## Honest limitations

These are in the code comments too, and are worth stating up front:

- Host-level overwriting cannot reach sectors the drive's own defect management
  has retired, nor an SSD's over-provisioned blocks. For media leaving a
  controlled environment, a firmware Purge or physical destruction is the only
  complete answer. FORGE reports unwritable sectors rather than hiding them.
- ATA/NVMe firmware sanitize is implemented on Linux (SG_IO and the NVMe admin
  ioctl) and Windows (`IOCTL_ATA_PASS_THROUGH`). macOS exposes no userspace
  pass-through without a kernel extension, so it falls back to overwriting and
  says so on the certificate.
- ext3/ext4 zero an inode's block pointers on delete. Metadata recovery there is
  limited to what the orphaned directory entries and surviving inodes give;
  carving does the rest. This is a property of the filesystem, not the tool.
- Carving cannot distinguish allocated from unallocated content unless the
  filesystem's allocation bitmap is readable — use `--unallocated-only` when it
  matters.

## Licence

See `LICENSE`.
