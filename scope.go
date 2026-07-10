package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Category is a normalized bucket for a scope asset.
type Category string

const (
	CatDomain   Category = "domains"
	CatWildcard Category = "wildcards"
	CatAPI      Category = "apis"
	CatMobile   Category = "mobile"
	CatCIDR     Category = "cidr"
	CatSource   Category = "source"
	CatOther    Category = "other"
)

var allCategories = []Category{CatDomain, CatWildcard, CatAPI, CatMobile, CatCIDR, CatSource, CatOther}

// ScopeAsset is one normalized in/out-of-scope entry.
type ScopeAsset struct {
	Identifier string   `json:"identifier"`
	RawType    string   `json:"raw_type"`
	Category   Category `json:"category"`
	Host       string   `json:"host,omitempty"`
	Wildcard   bool     `json:"wildcard"`
}

// Program is a normalized bug-bounty program.
type Program struct {
	Platform string       `json:"platform"`
	Name     string       `json:"name"`
	Handle   string       `json:"handle"`
	URL      string       `json:"url"`
	InScope  []ScopeAsset `json:"in_scope"`
	OutScope []ScopeAsset `json:"out_of_scope"`
}

// rawProgram is unmarshaled from bounty-targets-data. Field names differ per
// platform, so the asset lists are decoded as generic maps and read flexibly.
type rawProgram struct {
	Name          string `json:"name"`
	Handle        string `json:"handle"`
	CompanyHandle string `json:"company_handle"`
	ID            any    `json:"id"`
	URL           string `json:"url"`
	Targets       struct {
		InScope    []map[string]any `json:"in_scope"`
		OutOfScope []map[string]any `json:"out_of_scope"`
	} `json:"targets"`
}

var platformFiles = map[string]string{
	"hackerone": "hackerone_data.json",
	"bugcrowd":  "bugcrowd_data.json",
	"intigriti": "intigriti_data.json",
	"yeswehack": "yeswehack_data.json",
}

var platformOrder = []string{"hackerone", "bugcrowd", "intigriti", "yeswehack"}

const btdBaseURL = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/"

func assetIdentifier(m map[string]any) string {
	for _, k := range []string{"asset_identifier", "target", "endpoint", "uri", "asset", "url"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func assetType(m map[string]any) string {
	for _, k := range []string{"asset_type", "type"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

// categorize maps a raw type + identifier onto a normalized Category.
// Wildcards are detected from the identifier itself because some platforms
// label wildcard assets with generic types like "OTHER".
func categorize(rawType, id string) Category {
	t := strings.ToLower(strings.TrimSpace(rawType))
	if strings.Contains(id, "*") || strings.Contains(t, "wildcard") {
		return CatWildcard
	}
	if isCIDR(id) || containsAny(t, "cidr", "ip_range", "iprange", "ip range") {
		return CatCIDR
	}
	if containsAny(t, "android", "apple", "ios", "google_play", "googleplay", "apk", "testflight", "app_store", "appstore", "mobile") {
		return CatMobile
	}
	if containsAny(t, "source", "code") {
		return CatSource
	}
	host, _, ok := normalizeHost(id)
	if t == "api" {
		return CatAPI
	}
	webish := t == "" || t == "url" || t == "website" || t == "web" || t == "web-application" || t == "web_application"
	if ok && webish {
		if strings.HasPrefix(host, "api.") || strings.Contains(host, ".api.") || strings.HasPrefix(host, "api-") {
			return CatAPI
		}
		return CatDomain
	}
	if ok && t != "other" {
		return CatDomain
	}
	return CatOther
}

func toAsset(m map[string]any) (ScopeAsset, bool) {
	id := assetIdentifier(m)
	if id == "" {
		return ScopeAsset{}, false
	}
	rawType := assetType(m)
	host, wildcard, _ := normalizeHost(id)
	return ScopeAsset{
		Identifier: id,
		RawType:    rawType,
		Category:   categorize(rawType, id),
		Host:       host,
		Wildcard:   wildcard,
	}, true
}

func normalizeProgram(platform string, rp rawProgram) Program {
	p := Program{
		Platform: platform,
		Name:     strings.TrimSpace(rp.Name),
		Handle:   deriveHandle(rp),
		URL:      strings.TrimSpace(rp.URL),
	}
	for _, m := range rp.Targets.InScope {
		if a, ok := toAsset(m); ok {
			p.InScope = append(p.InScope, a)
		}
	}
	for _, m := range rp.Targets.OutOfScope {
		if a, ok := toAsset(m); ok {
			p.OutScope = append(p.OutScope, a)
		}
	}
	return p
}

func deriveHandle(rp rawProgram) string {
	if h := strings.TrimSpace(rp.Handle); h != "" {
		return h
	}
	if s, ok := rp.ID.(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	if u := strings.TrimRight(strings.TrimSpace(rp.URL), "/"); u != "" {
		if i := strings.LastIndex(u, "/"); i >= 0 && i+1 < len(u) {
			return u[i+1:]
		}
	}
	return slug(rp.Name)
}

func cacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "scan7x")
}

// fetchPlatform returns the raw program list for a platform, using a <24h cache
// when possible and falling back to any cached copy if the network fails.
func fetchPlatform(ctx context.Context, platform string, refresh bool) ([]rawProgram, error) {
	file, ok := platformFiles[platform]
	if !ok {
		return nil, fmt.Errorf("unknown platform %q", platform)
	}
	cachePath := filepath.Join(cacheDir(), file)
	if !refresh {
		if data, err := os.ReadFile(cachePath); err == nil && len(data) > 0 {
			if info, e := os.Stat(cachePath); e == nil && time.Since(info.ModTime()) < 24*time.Hour {
				var progs []rawProgram
				if json.Unmarshal(data, &progs) == nil {
					return progs, nil
				}
			}
		}
	}
	body, status, err := httpGetRetry(ctx, dataClient, btdBaseURL+file, 3)
	if err != nil || status != 200 {
		if data, e := os.ReadFile(cachePath); e == nil && len(data) > 0 {
			var progs []rawProgram
			if json.Unmarshal(data, &progs) == nil {
				logf("[warn] %s: network fetch failed, using cached scope data", platform)
				return progs, nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", platform, err)
		}
		return nil, fmt.Errorf("fetch %s: HTTP %d", platform, status)
	}
	var progs []rawProgram
	if err := json.Unmarshal(body, &progs); err != nil {
		return nil, fmt.Errorf("parse %s: %w", platform, err)
	}
	_ = os.MkdirAll(cacheDir(), 0o755)
	_ = os.WriteFile(cachePath, body, 0o644)
	return progs, nil
}

// searchPrograms searches the given platforms for programs whose name or handle
// fuzzy-matches the query.
func searchPrograms(ctx context.Context, platforms []string, query string, refresh bool) ([]Program, error) {
	q := squash(query)
	var results []Program
	var errs []string
	for _, plat := range platforms {
		progs, err := fetchPlatform(ctx, plat, refresh)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		for _, rp := range progs {
			if q == "" || strings.Contains(squash(rp.Name), q) || strings.Contains(squash(deriveHandle(rp)), q) {
				results = append(results, normalizeProgram(plat, rp))
			}
		}
	}
	if len(results) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return results, nil
}

func matchScore(p Program, q string) int {
	if q == "" {
		return 0
	}
	n, h := squash(p.Name), squash(p.Handle)
	switch {
	case n == q || h == q:
		return 3
	case strings.HasPrefix(n, q) || strings.HasPrefix(h, q):
		return 2
	default:
		return 1
	}
}

// rankPrograms sorts matches so the most relevant program is first.
func rankPrograms(results []Program, query string) {
	q := squash(query)
	sort.SliceStable(results, func(i, j int) bool {
		si, sj := matchScore(results[i], q), matchScore(results[j], q)
		if si != sj {
			return si > sj
		}
		return len(results[i].InScope) > len(results[j].InScope)
	})
}

func categoryIdentifiers(p Program) map[Category][]string {
	out := map[Category][]string{}
	for _, a := range p.InScope {
		out[a.Category] = append(out[a.Category], a.Identifier)
	}
	for k := range out {
		out[k] = dedupSorted(out[k])
	}
	return out
}

// enumRoots returns the wildcard roots (e.g. example.com from *.example.com)
// among the selected categories — these are what we enumerate subdomains for.
func enumRoots(assets []ScopeAsset, sel map[Category]bool) []string {
	var roots []string
	for _, a := range assets {
		if sel[a.Category] && a.Wildcard && a.Host != "" {
			roots = append(roots, a.Host)
		}
	}
	return dedupSorted(roots)
}

// knownHosts returns explicit (non-wildcard) in-scope hosts among selected
// categories. These are not expanded (that could leave scope) but are probed.
func knownHosts(assets []ScopeAsset, sel map[Category]bool) []string {
	var hosts []string
	for _, a := range assets {
		if sel[a.Category] && !a.Wildcard && a.Host != "" {
			hosts = append(hosts, a.Host)
		}
	}
	return dedupSorted(hosts)
}
