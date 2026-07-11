package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReconResult is the full aggregated output of a run.
type ReconResult struct {
	Program      Program
	OutDir       string
	Mode         string
	CatIDs       map[Category][]string
	Roots        []string
	KnownHosts   []string
	Subdomains   []string
	Resolved     []ResolvedHost
	EnumPerSrc   map[string]int
	LiveHosts    []LiveHost
	AllURLs      []string
	JSURLs       []string
	JSDownloaded []string
	Endpoints    []string
	Secrets      []Secret
	Started      time.Time
	Finished     time.Time
}

// writeOutputs persists every artifact plus the report and summary.
func writeOutputs(res *ReconResult) error {
	base := res.OutDir

	for _, c := range allCategories {
		if ids := res.CatIDs[c]; len(ids) > 0 {
			if err := writeLines(filepath.Join(base, "scope", string(c)+".txt"), ids); err != nil {
				return err
			}
		}
	}
	if b, err := json.MarshalIndent(res.Program, "", "  "); err == nil {
		_ = writeString(filepath.Join(base, "scope", "raw_program.json"), string(b))
	}
	if len(res.Roots) > 0 {
		_ = writeLines(filepath.Join(base, "scope", "roots.txt"), res.Roots)
	}
	if len(res.KnownHosts) > 0 {
		_ = writeLines(filepath.Join(base, "scope", "known_hosts.txt"), res.KnownHosts)
	}
	if len(res.Subdomains) > 0 {
		_ = writeLines(filepath.Join(base, "subdomains", "all.txt"), res.Subdomains)
	}
	if len(res.Resolved) > 0 {
		var lines, hostsOnly []string
		for _, r := range res.Resolved {
			lines = append(lines, fmt.Sprintf("%-50s %s", r.Host, strings.Join(r.IPs, ", ")))
			hostsOnly = append(hostsOnly, r.Host)
		}
		_ = writeLines(filepath.Join(base, "subdomains", "resolved.txt"), lines)
		_ = writeLines(filepath.Join(base, "subdomains", "resolved_hosts.txt"), hostsOnly)
	}
	if len(res.LiveHosts) > 0 {
		sort.Slice(res.LiveHosts, func(i, j int) bool { return res.LiveHosts[i].URL < res.LiveHosts[j].URL })
		var lines, urls []string
		for _, lh := range res.LiveHosts {
			srv := lh.Server
			if srv == "" {
				srv = "-"
			}
			lines = append(lines, fmt.Sprintf("%-3d  %-55s  [%-18s]  %s", lh.Status, lh.URL, truncateStr(srv, 18), lh.Title))
			urls = append(urls, lh.URL)
		}
		_ = writeLines(filepath.Join(base, "live", "live_hosts.txt"), lines)
		_ = writeLines(filepath.Join(base, "live", "live_urls.txt"), urls)
	}
	if len(res.AllURLs) > 0 {
		_ = writeLines(filepath.Join(base, "urls", "all_urls.txt"), res.AllURLs)
	}
	if len(res.JSURLs) > 0 {
		_ = writeLines(filepath.Join(base, "urls", "js_urls.txt"), res.JSURLs)
	}
	if len(res.Endpoints) > 0 {
		_ = writeLines(filepath.Join(base, "js", "endpoints.txt"), res.Endpoints)
	}
	if len(res.Secrets) > 0 {
		var lines []string
		for _, s := range res.Secrets {
			lines = append(lines, fmt.Sprintf("%-22s %s", s.Type, s.Match))
		}
		_ = writeLines(filepath.Join(base, "js", "secrets.txt"), lines)
	}
	if err := writeString(filepath.Join(base, "report.md"), buildReport(res)); err != nil {
		return err
	}
	return writeString(filepath.Join(base, "summary.json"), buildSummary(res))
}

func buildSummary(res *ReconResult) string {
	sc := map[string]int{}
	for c, ids := range res.CatIDs {
		sc[string(c)] = len(ids)
	}
	s := struct {
		Program      string         `json:"program"`
		Platform     string         `json:"platform"`
		Handle       string         `json:"handle"`
		URL          string         `json:"url"`
		Mode         string         `json:"mode"`
		GeneratedAt  string         `json:"generated_at"`
		DurationSec  float64        `json:"duration_seconds"`
		ScopeCounts  map[string]int `json:"scope_counts"`
		Roots        int            `json:"enumeration_roots"`
		Subdomains   int            `json:"subdomains"`
		Resolved     int            `json:"resolved"`
		LiveHosts    int            `json:"live_hosts"`
		URLs         int            `json:"urls"`
		JSFiles      int            `json:"js_files"`
		JSDownloaded int            `json:"js_downloaded"`
		Endpoints    int            `json:"endpoints"`
		Secrets      int            `json:"secrets"`
		EnumPerSrc   map[string]int `json:"enum_per_source"`
	}{
		Program:      res.Program.Name,
		Platform:     res.Program.Platform,
		Handle:       res.Program.Handle,
		URL:          res.Program.URL,
		Mode:         res.Mode,
		GeneratedAt:  res.Finished.UTC().Format(time.RFC3339),
		DurationSec:  res.Finished.Sub(res.Started).Seconds(),
		ScopeCounts:  sc,
		Roots:        len(res.Roots),
		Subdomains:   len(res.Subdomains),
		Resolved:     len(res.Resolved),
		LiveHosts:    len(res.LiveHosts),
		URLs:         len(res.AllURLs),
		JSFiles:      len(res.JSURLs),
		JSDownloaded: len(res.JSDownloaded),
		Endpoints:    len(res.Endpoints),
		Secrets:      len(res.Secrets),
		EnumPerSrc:   res.EnumPerSrc,
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return string(b)
}

func buildReport(res *ReconResult) string {
	var b strings.Builder
	p := res.Program
	fmt.Fprintf(&b, "# Recon Report — %s\n\n", nonEmpty(p.Name, p.Handle))
	fmt.Fprintf(&b, "> Generated by **scan7x** on %s · %.1fs · mode `%s`\n\n",
		res.Finished.UTC().Format("2006-01-02 15:04 UTC"), res.Finished.Sub(res.Started).Seconds(), res.Mode)

	b.WriteString("## Program\n\n")
	fmt.Fprintf(&b, "- **Platform:** %s\n", nonEmpty(p.Platform, "-"))
	fmt.Fprintf(&b, "- **Name:** %s\n", nonEmpty(p.Name, "-"))
	fmt.Fprintf(&b, "- **Handle:** %s\n", nonEmpty(p.Handle, "-"))
	if p.URL != "" {
		fmt.Fprintf(&b, "- **URL:** %s\n", p.URL)
	}

	b.WriteString("\n## Scope summary\n\n")
	b.WriteString("| Category | Count |\n|---|---:|\n")
	for _, c := range allCategories {
		if n := len(res.CatIDs[c]); n > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", c, n)
		}
	}
	fmt.Fprintf(&b, "| **in-scope assets (total)** | **%d** |\n", len(p.InScope))

	if res.Mode != "scope" {
		b.WriteString("\n## Enumeration & discovery\n\n")
		fmt.Fprintf(&b, "- **Wildcard roots enumerated:** %d\n", len(res.Roots))
		fmt.Fprintf(&b, "- **Subdomains discovered:** %d\n", len(res.Subdomains))
		if len(res.Resolved) > 0 {
			fmt.Fprintf(&b, "- **Resolving (DNS):** %d\n", len(res.Resolved))
		}
		if len(res.EnumPerSrc) > 0 {
			var keys []string
			for k := range res.EnumPerSrc {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%d", k, res.EnumPerSrc[k]))
			}
			fmt.Fprintf(&b, "- **Per source:** %s\n", strings.Join(parts, ", "))
		}
		if len(res.LiveHosts) > 0 {
			fmt.Fprintf(&b, "- **Live hosts:** %d\n", len(res.LiveHosts))
		}
		fmt.Fprintf(&b, "- **URLs (Wayback + crawl):** %d\n", len(res.AllURLs))
		fmt.Fprintf(&b, "- **JavaScript files:** %d (downloaded %d)\n", len(res.JSURLs), len(res.JSDownloaded))
		fmt.Fprintf(&b, "- **Endpoints extracted from JS:** %d\n", len(res.Endpoints))
		if len(res.Secrets) > 0 {
			fmt.Fprintf(&b, "- **Secrets / leads in JS:** %d ⚠️\n", len(res.Secrets))
		}

		if len(res.LiveHosts) > 0 {
			b.WriteString("\n### Live hosts (preview)\n\n```\n")
			for _, lh := range res.LiveHosts[:min(len(res.LiveHosts), 40)] {
				fmt.Fprintf(&b, "%-3d %s %s\n", lh.Status, lh.URL, lh.Title)
			}
			b.WriteString("```\n")
			if len(res.LiveHosts) > 40 {
				fmt.Fprintf(&b, "_… %d more in `live/live_hosts.txt`_\n", len(res.LiveHosts)-40)
			}
		}
		if len(res.Endpoints) > 0 {
			b.WriteString("\n### Endpoints from JS (preview)\n\n```\n")
			for _, e := range truncateList(res.Endpoints, 40) {
				b.WriteString(e + "\n")
			}
			b.WriteString("```\n")
			if len(res.Endpoints) > 40 {
				fmt.Fprintf(&b, "_… %d more in `js/endpoints.txt`_\n", len(res.Endpoints)-40)
			}
		}
		if len(res.Secrets) > 0 {
			b.WriteString("\n### Secrets / leads in JS ⚠️ (verify manually)\n\n```\n")
			for _, s := range res.Secrets[:min(len(res.Secrets), 40)] {
				fmt.Fprintf(&b, "%-22s %s\n", s.Type, s.Match)
			}
			b.WriteString("```\n")
			if len(res.Secrets) > 40 {
				fmt.Fprintf(&b, "_… %d more in `js/secrets.txt`_\n", len(res.Secrets)-40)
			}
		}
	}

	b.WriteString("\n## Output layout\n\n```\n")
	b.WriteString(fileTree(res))
	b.WriteString("```\n")

	b.WriteString("\n---\n\n### Responsible use\n\n")
	b.WriteString("Produced with passive OSINT sources plus light HTTP requests. Only interact with assets that are **explicitly in scope** for the program above, and follow its policy and rate limits. Reconnaissance is not authorization to exploit.\n")
	return b.String()
}

func fileTree(res *ReconResult) string {
	var b strings.Builder
	b.WriteString(filepath.Base(res.OutDir) + "/\n")
	b.WriteString("├─ report.md\n")
	b.WriteString("├─ summary.json\n")
	b.WriteString("├─ scope/\n")
	for _, c := range allCategories {
		if len(res.CatIDs[c]) > 0 {
			fmt.Fprintf(&b, "│   ├─ %s.txt\n", c)
		}
	}
	b.WriteString("│   └─ raw_program.json\n")
	if res.Mode != "scope" {
		if len(res.Subdomains) > 0 {
			b.WriteString("├─ subdomains/all.txt\n")
		}
		if len(res.Resolved) > 0 {
			b.WriteString("├─ subdomains/resolved.txt  (host → IPs)\n")
		}
		if len(res.LiveHosts) > 0 {
			b.WriteString("├─ live/live_hosts.txt\n")
		}
		if len(res.AllURLs) > 0 {
			b.WriteString("├─ urls/all_urls.txt + js_urls.txt\n")
		}
		if len(res.JSDownloaded) > 0 || len(res.Endpoints) > 0 {
			b.WriteString("├─ js/  (downloaded .js + endpoints.txt)\n")
		}
		if len(res.Secrets) > 0 {
			b.WriteString("└─ js/secrets.txt  ⚠️\n")
		}
	}
	return b.String()
}
