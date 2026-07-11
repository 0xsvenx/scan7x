# scan7x

[![CI](https://github.com/0xsvenx/scan7x/actions/workflows/ci.yml/badge.svg)](https://github.com/0xsvenx/scan7x/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/0xsvenx/scan7x?sort=semver)](https://github.com/0xsvenx/scan7x/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/0xsvenx/scan7x)](go.mod)
[![License](https://img.shields.io/github/license/0xsvenx/scan7x)](LICENSE)

**Pull a bug-bounty program's scope, then recon it — in one command.**
Pick a platform (HackerOne / Bugcrowd / Intigriti / YesWeHack), type a target
(e.g. `red bull`), choose what to pull (domains / APIs / wildcards / …), and
scan7x downloads the scope, enumerates subdomains, probes live hosts,
harvests JavaScript, extracts endpoints, and writes a clean report — all in Go,
with **zero external dependencies** and **no API keys required**.

```text
  ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██╗  ██╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║╚════██║╚██╗██╔╝
  ███████╗██║     ███████║██╔██╗ ██║    ██╔╝ ╚███╔╝
  ╚════██║██║     ██╔══██║██║╚██╗██║   ██╔╝  ██╔██╗
  ███████║╚██████╗██║  ██║██║ ╚████║   ██║  ██╔╝ ██╗
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝  ╚═╝  ╚═╝
        bug-bounty recon & enumeration engine
```

---

## Features

- 🎯 **Pick platform and target**: HackerOne, Bugcrowd, Intigriti, YesWeHack.
- 🗂️ **Automatic scope categorization**: domains, wildcards, APIs, mobile apps, CIDR, source, and other — each type in its own file.
- 🔎 **Passive subdomain enumeration** from many sources: certspotter, crt.sh, hackertarget, rapiddns, AlienVault OTX, urlscan.io.
- 🌐 **DNS resolution** (host → IPs) + **live-host probing** with status code, Server header, and page title.
- 🕸️ **Wayback URL harvesting** + **JavaScript** file extraction and download.
- 🧩 **Endpoint extraction** from JS files (paths and API routes).
- 🔑 **Secret / leak scanning** of JavaScript (AWS/GCP/JWT/Slack/Stripe/GitHub tokens, private keys, S3 buckets, …).
- 📄 **Clean final report** (`report.md` + `summary.json`) and organized folders.
- 🧱 Built in **Go**, zero external dependencies, runs on Windows/Linux/macOS.

---

## Install

### Prebuilt binary (no Go needed)

Download the archive for your OS/arch from the
[**Releases**](https://github.com/0xsvenx/scan7x/releases) page, extract it, and run:

```bash
# example (Linux amd64)
tar -xzf scan7x_v1.1.0_linux_amd64.tar.gz
./scan7x
```

### With Go (1.25+)

```bash
go install github.com/0xsvenx/scan7x@latest    # installs to $(go env GOPATH)/bin
```

or build from source:

```bash
git clone https://github.com/0xsvenx/scan7x.git
cd scan7x
go build -o scan7x .        # on Windows: go build -o scan7x.exe .
# or: make build
```

---

## Quick start

### 1) Interactive mode (easiest)

Run the tool with no options and it walks you through everything step by step:

```bash
./scan7x
```

```
Select platform:
  1) all
  2) hackerone
  3) bugcrowd
  4) intigriti
  5) yeswehack
Choice [1]: 3

Enter target program name (e.g. red bull): red bull

Scope found:
   - domains    12
   - wildcards  4
   - apis       2

What to pull? comma list (domains,apis,wildcards,...) or 'all'
Choice [all]: all

Recon depth:
  1) scope    — only download & categorize scope
  2) passive  — scope + passive subdomain enum + Wayback JS list
  3) full     — enum + live probe + crawl + download JS + endpoints
Choice [3]: 3
```

### 2) Flags (for automation)

```bash
# Search all platforms for "red bull" and run full recon
./scan7x -target "red bull"

# HackerOne only, pull domains and wildcards, passive recon
./scan7x -platform hackerone -target uber -pull domains,wildcards -recon passive

# Just pull and categorize scope, no recon
./scan7x -target shopify -recon scope

# Skip the platform lookup and recon directly on domains you already know
./scan7x -root example.com,api.example.com -recon full -o ./out/example
```

---

## How it works (the flow)

```
platform + target  ─▶  scope (categorized)  ─▶  enumeration  ─▶  live probe
                                                      │
                                                      ▼
   report.md  ◀─  endpoints  ◀─  download JS  ◀─  Wayback URLs + crawl
```

1. **Scope**: Program data is pulled from the `bounty-targets-data` project (updated
   daily, no keys needed) and assets are auto-categorized. Scope is cached locally
   for 24 hours (`-refresh` to force an update).
2. **Enumeration**: Subdomains are gathered only for **wildcard roots** (e.g.
   `*.example.com`) from passive sources. Explicit non-wildcard hosts are never
   expanded, to stay within scope.
3. **Resolve & probe** (in `full` mode): subdomains are resolved via DNS
   (host → IPs), and the resolvable ones are checked over HTTPS then HTTP.
4. **URLs + JS**: URLs are collected from Wayback and live host pages are crawled
   for `<script src>` tags, then in-scope JS files are downloaded, and endpoints
   **and secrets** are extracted from them.
5. **Report**: a report, summary, and organized folders are written to disk.

---

## Projects (persistent recon + diff)

Track a target over time in a real **SQLite** database (`~/.scan7x/scan7x.db`,
openable with `sqlite3`/DBeaver). Re-scan whenever you want and scan7x tells you
exactly **what's new** — new subdomains, new live hosts, and even new assets the
program added to its scope.

```bash
# create a project bound to a program and run the first scan
scan7x project create shopify -platform hackerone -target shopify

# re-scan later — highlights NEW subdomains / scope assets since last time
scan7x project update shopify

scan7x project list                 # all projects, with counts
scan7x project show shopify         # stats for one project
scan7x project report shopify       # (re)generate report.md from the database
scan7x project delete shopify
```

Example diff on an update:

```
  ▲ NEW SINCE LAST SCAN

  NEW SCOPE ASSET (1)
    + *.checkout.shopify.com
  NEW SUBDOMAIN (3)
    + api-edge.shopify.com
    + staging-2.shopify.com
    + internal-tools.shopify.com
```

> The database lives under `~/.scan7x/` (override the base dir with
> `SCAN7X_HOME`, or the DB path with `SCAN7X_DB`).

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `-platform` | `all` | `hackerone` \| `bugcrowd` \| `intigriti` \| `yeswehack` \| `all` |
| `-target` | — | Program name/handle to search for (e.g. `"red bull"`) |
| `-pull` | `all` | Scope categories: `domains,wildcards,apis,mobile,cidr,source,other,all` |
| `-pick` | `0` | When multiple programs match, pick result N |
| `-recon` | `full` | `scope` \| `passive` \| `full` |
| `-o` | `./output/<platform>_<handle>` | Output directory |
| `-root` | — | Skip scope lookup and recon these domains directly (comma-separated list) |
| `-sources` | `certspotter,crtsh,hackertarget,rapiddns,otx,urlscan` | Subdomain sources (also available: `anubis`, `subdomaincenter`) |
| `-threads` | `25` | Concurrency for probing/crawling/downloading |
| `-timeout` | `15` | Per-request timeout in seconds when touching targets |
| `-wayback-limit` | `20000` | Max URLs per target from Wayback (0 = unlimited) |
| `-refresh` | `false` | Force a refresh of the cached scope data |
| `-silent` | `false` | Suppress banner and progress (quiet mode) |
| `-y` | `false` | Non-interactive mode (no prompts) |
| `-no-color` | `false` | Disable colored output |
| `-version` | — | Print the version and exit |

---

## Output layout

```
output/<platform>_<handle>/
├─ report.md                 ← the final human-readable report
├─ summary.json              ← JSON summary (counts + paths)
├─ scope/
│   ├─ domains.txt
│   ├─ wildcards.txt
│   ├─ apis.txt
│   ├─ mobile.txt / cidr.txt / source.txt / other.txt
│   ├─ roots.txt             ← wildcard roots used for enumeration
│   └─ raw_program.json      ← the full normalized scope
├─ subdomains/
│   ├─ all.txt               ← all discovered subdomains
│   └─ resolved.txt          ← resolvable hosts → IPs
├─ live/
│   ├─ live_hosts.txt        ← status + url + [server] + title
│   └─ live_urls.txt
├─ urls/
│   ├─ all_urls.txt          ← Wayback + crawl URLs
│   └─ js_urls.txt
└─ js/
    ├─ <host>_<file>.js      ← downloaded JS files (deduplicated)
    ├─ endpoints.txt         ← extracted endpoints
    └─ secrets.txt           ← possible secrets / leads ⚠️
```

---

## Data sources

All public, no keys required:

- **Scope**: [`arkadiyt/bounty-targets-data`](https://github.com/arkadiyt/bounty-targets-data) (aggregates public HackerOne/Bugcrowd/Intigriti/YesWeHack scope daily).
- **Subdomains**: certspotter, crt.sh, hackertarget, rapiddns, AlienVault OTX, urlscan.io.
- **DNS**: your system resolver (host → IPs).
- **URLs/JS**: Wayback Machine (web.archive.org) + light direct crawling.

Rate-limited sources are handled gracefully: if a source is down or over its
limit, the tool continues with the rest without stopping.

---

## Responsible use ⚠️

This is a **reconnaissance** tool for use on authorized bug-bounty programs.

- Only interact with assets that are **explicitly in scope** for the program,
  and follow its policy and rate limits.
- Reconnaissance is **not authorization to exploit**.
- Most steps are passive (certificate/archive records), but probing and JS
  downloading send light HTTP requests to targets — only use this where you
  have permission.

Legal responsibility rests with the user.

---

## Tested

- CI runs `gofmt`, `go vet ./...`, `go test ./...`, and `go build ./...` on every push.
- A real end-to-end run against `owasp.org`: 56 subdomains (all resolvable),
  55 live hosts, 160 JS files, 575 extracted endpoints, and 2 JWTs flagged in
  JavaScript — with graceful handling when some sources were down.

---

## License

[MIT](LICENSE)
