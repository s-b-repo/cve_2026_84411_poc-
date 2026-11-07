#  CVE-2026-84411 (RouterOS WebFig Pre-Auth Heap Overflow)

**Analyst:** Stephan Botes 
**Target:** MikroTik RouterOS < 7.24 (stable) / < 7.23.8 (LT) — verified on CCR2004-1G-12S+2XS, RouterOS 7.22.1
**Surface:** `POST /jsproxy` (WebFig, port 80) — **unauthenticated**

---

## Contents

| File | Description |
|------|-------------|
| `cve_2026_84411_poc.py` | PoC exploit — probe / trigger / crash / session modes |
| `start_chr_lab.sh` | Launch MikroTik CHR 7.22.1 lab under QEMU with test ports |
| `CVE-2026-84411_FINDINGS.md` | Full findings: root cause, patch diff, heap analysis, CVE inventory |

---

## Vulnerability Summary

Pre-authentication integer underflow in the RouterOS WebFig HTTP body receiver (`nova/bin/www`).
At `sub r2, r2, r1` (ARM `0x1f9a4` / x86 `0x8057626`) the remaining length is computed as
`capacity - received` with no bounds check. When `received > capacity` the value wraps to
`~0xFFFFFFFF`, so `read()` pulls attacker-controlled socket data far past the 512-byte heap
buffer. Fixed in 7.25.1 by a `cmp`/`bls` guard (`0x1f71c`).

**Binary protections (7.22.1):** NX=on, **PIE=off**, RELRO=partial (**GOT writable**), **no canary**
→ GOT overwrite + ROP is the exploitation path.

**Confirmed trigger:** `POST /jsproxy` with `Content-Type: msg` (must precede `Content-Length`),
`Content-Length: 32`, actual body ≥ 517 bytes → permanent `www` process death (no auto-restart).
Full X25519 + RC4 (768-byte key drop) jsproxy session established — see findings §9.6.

---

## Requirements

- Python 3 with the `cryptography` package (used for X25519 handshake session mode)
- QEMU (`qemu-system-x86_64`, `qemu-img`) for the CHR lab

## Lab Setup

```bash
# 1. Build the CHR image (one-time; see script for exact commands)
wget https://download.mikrotik.com/routeros/7.22.1/chr-7.22.1.img.zip -O /tmp/chr-7.22.1.img.zip
cd /tmp && unzip chr-7.22.1.img.zip
qemu-img convert -f raw -O qcow2 chr-7.22.1.img chr-7221.qcow2
qemu-img resize chr-7221.qcow2 512M

# 2. Start the lab (WebFig → localhost:18080, WinBox → :18291, SSH → :12222)
./start_chr_lab.sh
```

Login: `admin` / (empty password). WebFig: http://localhost:18080

## PoC Usage

```bash
python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode probe    # safe recon + handshake attempt
python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode session  # full encrypted jsproxy session
python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode crash    # CONFIRMED crash trigger (destructive)
python3 cve_2026_84411_poc.py 127.0.0.1 18080 --mode all      # probe + crash
```

**WARNING:** `--mode crash` and `--mode trigger` kill the `www` process on vulnerable builds.
Lab use only. Do not run against production systems without explicit written authorization.

---

## Status & Remaining Work

| Milestone | Status |
|-----------|--------|
| Root cause identified (patch diff 7.22.1 vs 7.25.1) | Done |
| Binary protections mapped (no PIE / no canary / writable GOT) | Done |
| jsproxy protocol reversed (header order, X25519 BE, RC4) | Done |
| Pre-auth crash confirmed (permanent `www` death) | Done |
| Controlled heap overflow / chunk-metadata corruption | In progress |
| ROP chain (x86 CHR first, then ARM for CCR2004) | Pending |
| Full RCE PoC | Pending |

Key primitives for the ROP chain (x86 CHR): GOT.PLT base `0x08068000` (writable),
`free@GOT` `0x08068414`, `.text` base `0x0804f380`, gadgets at `0x0804f3d7` / `0x080527be` /
`0x0805a784`. Suggested path: `mmap(RWX)` → `read(fd, addr, len)` → jump to shellcode.

## Remediation

Upgrade to **RouterOS 7.24.5 (stable)** or later (7.25.1 contains the specific fix). Avoid 7.23.x
(WebFig fix only in ≥7.23.8 LT) and 7.24.2 (misses CVE-2026-67278).
