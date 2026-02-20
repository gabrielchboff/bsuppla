# Usage Guide

This guide explains how to build and run **bsuppla**, including optional allowlists and environment variables.

## Build
```bash
cd bsuppla/bsuppla
cargo build --release
```

Binary:
```
bsuppla/bsuppla/target/release/bsuppla
```

## Install
```bash
bash scripts/install.sh
```

Or via Make:
```bash
make install
```

## Run
```bash
bsuppla <image> <image.tar> [allowlist.txt]
```

Example:
```bash
bsuppla alpine:latest alpine.tar allowlist.txt
```

With baseline:
```bash
bsuppla alpine:latest alpine.tar allowlist.txt baseline.txt
```

With baseline export:
```bash
bsuppla alpine:latest alpine.tar allowlist.txt baseline.txt --baseline-out new-baseline.txt
```

If you prefer `cargo run`:
```bash
cargo run -- <image> <image.tar> [allowlist.txt]
```

## Allowlist
Optional text file with **one path per line**. Lines starting with `#` are comments. Paths are interpreted as root‑relative inside the image.

Entries can also be kind‑specific:
```
<kind>: <path-or-pattern>
```
Patterns support `*` and `?`.

If no allowlist is provided, a built‑in default allowlist is used for
`elf_suspicious` findings in standard library and binary locations.

Example:
```txt
# Alpine common items
/bin/busybox
/sbin/apk
/usr/lib/libcrypto.so.3
/usr/lib/libssl.so.3

# Kind-specific pattern
elf_suspicious: /usr/lib/*
```

## Baseline
Optional text file with lines in the format:
```
<kind>: <path>
```

Example:
```txt
elf_suspicious: /bin/busybox
startup_script_present: /var/spool/cron/crontabs/root
```

When provided, the scan prints **new** findings and highlights any **missing** baseline entries.

To generate a baseline file from the current scan:
```bash
bsuppla alpine:latest alpine.tar allowlist.txt --baseline-out baseline.txt
```

## Environment Variables
- `BSUPPLA_SKIP_DOCKER=1`  
  Skip `docker pull`/`docker save` and scan an existing tar.
- `BSUPPLA_SKIP_SCAN=1`  
  Skip scanning after extraction.
- `BSUPPLA_OUTPUT_DIR=/path`  
  Set extraction directory (default: `container_fs`).

## Output
The scanner prints a list of findings (if any) and a final **Suspicion level**.

Example:
```
[+] Findings:
 - elf_suspicious: sbin/apk (stripped)
 - startup_script_present: var/spool/cron/crontabs/root (init/rc/cron)
[+] Suspicion level: medium
```

High-severity example:
```
[+] Findings:
 - crypto_miner_candidate: usr/bin/xmrig (known miner name)
 - private_key_candidate: root/.ssh/id_rsa (key material present)
 - suid_or_sgid_executable: usr/bin/sudo (mode=4755)
 - apk_repository_suspicious: etc/apk/repositories (non-alpine repo: http://example.com/alpine)
[+] Suspicion level: high
```

## Help
```bash
bsuppla --help
```
