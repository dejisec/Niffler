# Niffler

[![CI](https://github.com/dejisec/niffler/actions/workflows/ci.yml/badge.svg)](https://github.com/dejisec/niffler/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/dejisec/niffler)](https://github.com/dejisec/niffler/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)

Niffler scans NFS servers for credentials, secrets, and misconfigurations. Think [Snaffler](https://github.com/SnaffCon/Snaffler), but for NFS instead of SMB.

## Why NFS?

NFS (especially v3) uses AUTH_SYS authentication, which sends UID/GID values in plaintext and the server blindly trusts them. There's no password, no Kerberos ticket, no challenge-response. If you can reach the NFS port, you can claim to be any non-root user on the system and read their files, or even root if `no_root_squash` is set.

Niffler automates the tedious parts: discovering exports, walking directory trees, spoofing UIDs, and pattern-matching file content against a library of credential signatures.

## Quick Start

### Install

**Option 1** — Download a prebuilt binary from the [Releases](https://github.com/dejisec/niffler/releases) page.

**Option 2** — Install via cargo (requires [libnfs-dev](https://github.com/sahlberg/libnfs)):

```bash
cargo install --git https://github.com/dejisec/niffler
```

**Option 3** — Build from source (requires [libnfs-dev](https://github.com/sahlberg/libnfs)):

```bash
git clone https://github.com/dejisec/niffler && cd niffler
cargo build --release
cp target/release/niffler .
```

```bash
# Scan a single NFS server
./niffler scan -t 10.0.0.5

# Scan a subnet
./niffler scan -t 192.168.1.0/24

# Just recon — list servers, exports, and misconfigs without touching files
./niffler scan -t 10.0.0.0/24 --mode recon

# Browse results in the web dashboard
./niffler serve --db niffler.db

# Export findings as JSON
./niffler export --db niffler.db -f json
```

## Operating Modes

Niffler runs in three modes, so you can dial in how deep you want to go:

| Mode | What it does | Use when... |
|------|-------------|-------------|
| `recon` | Finds NFS servers, lists exports, checks for misconfigurations | You want a quiet lay of the land |
| `enum` | Above + walks directory trees, matches filenames against rules | You want to see what's there without reading file content |
| `scan` | Above + reads file content and applies regex patterns | You want the full picture (default) |

```bash
./niffler scan -t 10.0.0.0/24 -m recon    # Discovery only
./niffler scan -t 10.0.0.0/24 -m enum     # Discovery + tree walk
./niffler scan -t 10.0.0.0/24             # Full scan (default)
```

## Usage Examples

```bash
# Scan and only show high-severity findings (Red and Black)
./niffler scan -t nfs-server.internal -b red

# Scan with live console output alongside database write
./niffler scan -t nfs-server.internal --live

# Scan as a specific user (e.g., UID 1000 found during recon)
./niffler scan -t nfs-server.internal --uid 1000 --gid 1000

# Scan through a SOCKS5 proxy
./niffler scan -t 10.0.0.5 --proxy socks5://127.0.0.1:1080

# Scan local/mounted NFS shares directly (no network discovery)
./niffler scan -i /mnt/nfs_share1 /mnt/nfs_share2

# Read targets from a file (one per line, supports CIDR)
./niffler scan -T targets.txt

# Read targets from stdin
cat targets.txt | ./niffler scan -T -

# Check for subtree_check bypass (filehandle escape from export boundary)
./niffler scan -t 192.168.0.0/16 --check-subtree-bypass

# Write results to a custom database path
./niffler scan -t 10.0.0.0/24 -o engagement.db

# Generate a config template, tweak it, and reuse
./niffler scan -z > niffler.toml
# (edit niffler.toml to taste)
./niffler scan -c niffler.toml -t 10.0.0.0/24

# Launch the web dashboard to review findings
./niffler serve --db niffler.db
./niffler serve --db niffler.db --port 9090 --bind 0.0.0.0

# Export findings from the database
./niffler export --db niffler.db -f json
./niffler export --db niffler.db -f csv -b red
./niffler export --db niffler.db -f tsv --host 10.0.0.5 --scan-id 3
```

## Output

All scan results are written to a SQLite database (`niffler.db` by default).

### Live Console (`--live`)

Add `--live` to see findings in the terminal as they're discovered, alongside the database write:

```
[2026-03-17 14:23:01] [BLACK] [SshPrivateKeys] [RW-] nfs-server:/exports/home/user1/.ssh/id_rsa (1.7 KB, uid:1001, gid:1001, 2025-11-03)
[2026-03-17 14:23:02] [RED] [CredentialPatterns] [RW-] nfs-server:/exports/app/.env (423 B, uid:1000, gid:1000, 2026-01-15)
    Context: "DB_PASSWORD=s3cretP@ss123"
[2026-03-17 14:23:03] [RED] [AwsAccessKeys] [RW-] nfs-server:/exports/home/deploy/.aws/credentials (240 B, uid:1002, gid:1002, 2025-09-22)
    Context: "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
```

### Web Dashboard (`serve`)

Launch a local web UI for interactive triage — filter, star, and review findings in your browser:

```bash
./niffler serve --db niffler.db
# Open http://127.0.0.1:8080
```

### Export (`export`)

Export findings from the database as JSON lines, CSV, or TSV:

```bash
./niffler export --db niffler.db -f json                 # JSON lines to stdout
./niffler export --db niffler.db -f csv -b red           # CSV, Red and Black only
./niffler export --db niffler.db -f tsv --host 10.0.0.5  # TSV, single host
```

## Severity Levels

Findings are triaged into four levels. Use `-b` to set a minimum severity threshold.

| Level | Meaning | Examples |
|-------|---------|----------|
| **Black** | Immediate, direct impact — usable credentials or key material | SSH private keys, shadow files, Vault tokens, KeePass databases |
| **Red** | High-value — likely contains secrets, needs a closer look | `.env` files with passwords, AWS access keys, database connection strings |
| **Yellow** | Interesting — worth noting but may not be directly exploitable | Config files, log files with potential info |
| **Green** | Informational — context that helps paint the bigger picture | Scripts, documentation, data files on interesting exports |

```bash
./niffler scan -t 10.0.0.5 -b red      # Only Red and Black findings
./niffler scan -t 10.0.0.5 -b black    # Only Black findings
```

## How It Works

Niffler runs as a multi-phase async pipeline:

```
Targets ──► Discovery ──► Tree Walker ──► File Scanner ──► Output
              │                │                │
         find servers     walk exports     read content
         list exports     prune junk dirs  match filenames
         harvest UIDs                      match patterns
         detect misconfig                  check for keys
                                           UID cycling
```

**Discovery** finds NFS servers (port scan on 111/2049), queries the portmapper and MOUNT service for exports, harvests UIDs from directory listings, and checks for misconfigurations.

**Tree Walker** does a recursive READDIRPLUS traversal of each export, applying directory discard rules to prune uninteresting paths early.

**File Scanner** reads file content and runs it through the rule engine. If a file is permission-denied, Niffler automatically cycles through harvested UIDs (AUTH_SYS spoofing) to try accessing it as different users.

**UID Cycling** is the secret sauce. When the scanner hits a permission wall, it tries:

1. The primary UID (from `--uid`/`--gid`, default: nobody/65534)
2. The file's owning UID (from stat — most likely to work)
3. UIDs harvested during discovery (from directory listings)

Each UID attempt creates a new NFS connection with fresh AUTH_SYS credentials. NFS file handles are cross-connection valid, so a handle obtained by the walker can be read by the scanner using a completely different UID.

## Rule Engine

Rules are defined in TOML and compiled into the binary. The engine uses a **relay-chain architecture** (borrowed from Snaffler): cheap rules gate expensive ones.

For example, a file named `.env` first matches a filename rule (instant). That rule *relays* to content rules, which read the file and apply regex patterns (expensive). This way, regex only runs on files that are likely to contain something interesting.

```
.env file found
  └─► FileEnumeration rule matches ".env" (Relay action)
        ├─► CredentialPatterns: scans for password=, api_key=, bearer tokens, etc.
        ├─► CloudKeyPatterns: scans for AKIA..., aws_secret_access_key, etc.
        └─► TokenPatterns: scans for Slack xox*, GitHub ghp_, JWT, etc.
```

Rules have four scopes:

- **ShareEnumeration** — applied to export paths during discovery
- **DirectoryEnumeration** — applied to directory names during tree walk
- **FileEnumeration** — applied to filenames/extensions/paths in the scanner
- **ContentsEnumeration** — applied to file content (most expensive, gated by relays)

### Custom Rules

Replace the defaults entirely or merge your own rules on top:

```bash
# Replace all built-in rules with your own
./niffler scan -t 10.0.0.5 -r /path/to/my-rules/

# Keep defaults and add extra rules
./niffler scan -t 10.0.0.5 -R /path/to/extra-rules/
```

Rules are TOML files with a straightforward structure:

```toml
[[rules]]
name = "MyCustomPattern"
scope = "ContentsEnumeration"
match_location = "FileContentAsString"
match_type = "Regex"
patterns = ['(?i)internal_api_key\s*=\s*["\'][^"\']{16,}']
action = "Snaffle"
triage = "Red"
max_size = 1048576
context_bytes = 200
description = "Custom internal API key pattern"
```

## Misconfiguration Detection

During discovery, Niffler probes each export for common NFS misconfigurations:

| Check | What it means | How Niffler tests it |
|-------|---------------|---------------------|
| **no_root_squash** | Server trusts UID 0 — you can read/write anything as root | Connects as UID 0, attempts `getattr` on the export root |
| **insecure** | Export accepts connections from unprivileged ports (>1024) | Connects from a high port, checks if `getattr` succeeds |
| **subtree_check bypass** | File handles can escape the export boundary | Looks up `..` from the export root, checks if the returned handle differs |

```bash
# Enable subtree bypass check (off by default, adds extra probe per export)
./niffler scan -t 10.0.0.0/24 --check-subtree-bypass
```

## CLI Reference

### Global Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-v, --verbosity` | Log level: `trace`, `debug`, `info`, `warn`, `error` | `info` |

### `niffler scan` — Scan NFS shares for secrets

#### Targets

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --targets` | IP addresses, hostnames, or CIDR ranges | — |
| `-T, --target-file` | Read targets from file (one per line, `-` for stdin) | — |
| `-i, --local-path` | Scan local/mounted paths instead of NFS discovery | — |

#### Mode & Output

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --mode` | Operating mode: `recon`, `enum`, `scan` | `scan` |
| `-o, --output` | SQLite database path for results | `niffler.db` |
| `-l, --live` | Print findings to terminal alongside database write | `false` |
| `-b, --min-severity` | Minimum triage level: `green`, `yellow`, `red`, `black` | `green` |

#### NFS Authentication

| Flag | Description | Default |
|------|-------------|---------|
| `--uid` | UID for AUTH_SYS credentials | `65534` (nobody) |
| `--gid` | GID for AUTH_SYS credentials | `65534` (nobody) |
| `--uid-cycle` | Auto-cycle through harvested UIDs on permission denied | `true` |
| `--max-uid-attempts` | Max UID attempts per file before giving up | `5` |
| `--nfs-version` | Force NFS version (auto-detect if not set) | — |
| `--privileged-port` | Bind source port < 1024  | `true` |
| `--proxy` | SOCKS5 proxy URL (e.g., `socks5://127.0.0.1:1080`) | — |

#### Concurrency & Limits

| Flag | Description | Default |
|------|-------------|---------|
| `--max-connections-per-host` | Max concurrent NFS connections per server | `8` |
| `--discovery-tasks` | Max concurrent discovery tasks | `30` |
| `--discovery-timeout` | Timeout in seconds for network operations | `5` |
| `--walker-tasks` | Max concurrent tree walk tasks (one per export) | `20` |
| `--scanner-tasks` | Max concurrent file scan tasks | `50` |
| `--max-depth` | Max directory depth during tree walk | `50` |
| `--walk-retries` | Max retries per export walk on transient errors | `2` |
| `--walk-retry-delay` | Base delay between retries (ms, scales linearly) | `500` |
| `--max-scan-size` | Max file size to read content from (bytes) | `1048576` (1 MB) |

#### Rules & Config

| Flag | Description | Default |
|------|-------------|---------|
| `-r, --rules-dir` | Custom rules directory (replaces defaults) | — |
| `-R, --extra-rules` | Additional rules directory (merged with defaults) | — |
| `-c, --config` | Load config from TOML file | — |
| `-z, --generate-config` | Print current config as TOML and exit | `false` |
| `--check-subtree-bypass` | Enable subtree_check bypass detection | `false` |

### `niffler serve` — Launch web dashboard

| Flag | Description | Default |
|------|-------------|---------|
| `--db` | Path to SQLite database (required) | — |
| `--port` | Port to listen on | `8080` |
| `--bind` | Address to bind to | `127.0.0.1` |

### `niffler export` — Export findings to stdout

| Flag | Description | Default |
|------|-------------|---------|
| `--db` | Path to SQLite database (required) | — |
| `-f, --format` | Output format: `json`, `csv`, `tsv` (required) | — |
| `-b, --min-severity` | Minimum triage level filter | — |
| `--host` | Filter by host | — |
| `--rule` | Filter by rule name | — |
| `--scan-id` | Filter by scan ID | — |
