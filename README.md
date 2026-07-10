# scan7x

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
- 🔎 **Passive subdomain enumeration** from multiple sources: certspotter, crt.sh, hackertarget, rapiddns, AlienVault OTX.
- 🌐 **Live-host probing** with status code and page title.
- 🕸️ **Wayback URL harvesting** + **JavaScript** file extraction and download.
- 🧩 **Endpoint extraction** from JS files (paths and API routes).
- 📄 **Clean final report** (`report.md` + `summary.json`) and organized folders.
- 🧱 Built in **Go**, zero external dependencies, runs on Windows/Linux/macOS.

---

## Requirements & install

You only need **Go 1.22+**. Download it from <https://go.dev/dl/>.

```bash
git clone https://github.com/0xsvenx/scan7x.git
cd scan7x
go build -o scan7x ./...      # on Windows: go build -o scan7x.exe ./...
```

After building you'll have a single executable named `scan7x` (or `scan7x.exe`).

> You can also run `go install github.com/0xsvenx/scan7x@latest` to install
> it directly (requires Go 1.22+ and `$(go env GOPATH)/bin` on your `PATH`).

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
3. **Probe** (in `full` mode): each host is checked over HTTPS then HTTP and live
   ones are recorded.
4. **URLs + JS**: URLs are collected from Wayback and live host pages are crawled
   for `<script src>` tags, then in-scope JS files are downloaded and endpoints
   are extracted from them.
5. **Report**: a report, summary, and organized folders are written to disk.

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
| `-sources` | `certspotter,crtsh,hackertarget,rapiddns,otx` | Subdomain sources |
| `-threads` | `25` | Concurrency for probing/crawling/downloading |
| `-timeout` | `15` | Per-request timeout in seconds when touching targets |
| `-wayback-limit` | `20000` | Max URLs per target from Wayback (0 = unlimited) |
| `-refresh` | `false` | Force a refresh of the cached scope data |
| `-y` | `false` | Non-interactive mode (no prompts) |
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
├─ subdomains/all.txt        ← all discovered subdomains
├─ live/
│   ├─ live_hosts.txt        ← status + url + title
│   └─ live_urls.txt
├─ urls/
│   ├─ all_urls.txt          ← Wayback + crawl URLs
│   └─ js_urls.txt
└─ js/
    ├─ <host>_<file>.js      ← downloaded JS files (deduplicated)
    └─ endpoints.txt         ← extracted endpoints
```

---

## Data sources

All public, no keys required:

- **Scope**: [`arkadiyt/bounty-targets-data`](https://github.com/arkadiyt/bounty-targets-data) (aggregates public HackerOne/Bugcrowd/Intigriti/YesWeHack scope daily).
- **Subdomains**: certspotter, crt.sh, hackertarget, rapiddns, AlienVault OTX.
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

- `go vet ./...` and `gofmt` are clean, and `go test ./...` (unit tests for
  parsing, categorization, and denoising) passes.
- A real end-to-end run against `owasp.org`: 56 subdomains, 55 live hosts,
  156 JS files, and 572 extracted endpoints — with graceful handling when
  some sources were down.

---

## License

[MIT](LICENSE)
