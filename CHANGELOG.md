# Changelog

## v1.1.0

### Added
- **DNS resolution** step — `subdomains/resolved.txt` (host → IPv4/IPv6); only the resolvable subset is probed.
- **Secret / leak scanning** of downloaded JavaScript — `js/secrets.txt` (AWS, GCP, JWT, Slack, Stripe, GitHub tokens, private keys, S3 buckets, generic API keys, …).
- New passive source **urlscan.io**. `anubis` and `subdomaincenter` are registered for opt-in use via `-sources`.
- **Richer live-host output** — Server header, content length, and redirect location in `live/live_hosts.txt`.
- `-silent` quiet mode (suppresses banner and progress).
- **Prebuilt binaries** via GitHub Releases; CI (vet + test + build + gofmt) on every push.

### Changed
- Per-source 25s timeout so one slow source can't stall enumeration.
- `version`/`commit` are injected at build time (`-ldflags`); `-version` shows both.

### Interactive wizard
- Numbered category selection (was free-text).
- Strict platform validation (invalid numbers re-ask instead of silently defaulting).
- Change platform between scans; `exit`/`quit`/`q` at any prompt; retries on bad input.
- Animated gradient banner.

## v1.0.0
- Initial release: scope pull (HackerOne / Bugcrowd / Intigriti / YesWeHack), passive subdomain enumeration, live-host probing, Wayback URL + JavaScript harvesting, endpoint extraction, and an organized output folder with `report.md`.
