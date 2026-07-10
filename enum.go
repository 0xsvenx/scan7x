package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

var defaultSources = []string{"certspotter", "crtsh", "hackertarget", "rapiddns", "otx"}

type sourceFunc func(ctx context.Context, root string) ([]string, error)

func sourceRegistry() map[string]sourceFunc {
	return map[string]sourceFunc{
		"certspotter":  srcCertspotter,
		"crtsh":        srcCrtsh,
		"hackertarget": srcHackertarget,
		"rapiddns":     srcRapiddns,
		"otx":          srcOTX,
	}
}

// EnumResult holds the merged subdomains and per-source stats for one root.
type EnumResult struct {
	Root       string
	Subdomains []string
	PerSource  map[string]int
	Errors     map[string]string
}

// enumerateRoot queries every configured source concurrently for one root.
func enumerateRoot(ctx context.Context, root string, sources []string) EnumResult {
	reg := sourceRegistry()
	res := EnumResult{Root: root, PerSource: map[string]int{}, Errors: map[string]string{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	var all []string
	for _, name := range sources {
		fn, ok := reg[name]
		if !ok {
			continue
		}
		wg.Add(1)
		go func(name string, fn sourceFunc) {
			defer wg.Done()
			subs, err := fn(ctx, root)
			filtered := filterScopeHosts(subs, root)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				res.Errors[name] = err.Error()
			}
			res.PerSource[name] = len(filtered)
			all = append(all, filtered...)
		}(name, fn)
	}
	wg.Wait()
	all = append(all, root)
	res.Subdomains = dedupSorted(all)
	return res
}

// enumerateAll runs enumeration for each root sequentially (gentle on
// rate-limited sources) and returns the merged set plus aggregate stats.
func enumerateAll(ctx context.Context, roots, sources []string) ([]string, map[string]int, []EnumResult) {
	agg := map[string]int{}
	var all []string
	var results []EnumResult
	for idx, root := range roots {
		select {
		case <-ctx.Done():
			return dedupSorted(all), agg, results
		default:
		}
		logf("  [enum %d/%d] %s", idx+1, len(roots), root)
		r := enumerateRoot(ctx, root, sources)
		results = append(results, r)
		all = append(all, r.Subdomains...)
		for k, v := range r.PerSource {
			agg[k] += v
		}
		logf("      -> %d subdomains", len(r.Subdomains))
	}
	return dedupSorted(all), agg, results
}

// filterScopeHosts keeps only hosts that belong to root (root itself or a
// subdomain of it) and are syntactically valid.
func filterScopeHosts(hosts []string, root string) []string {
	root = strings.ToLower(strings.TrimSpace(root))
	var out []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimSuffix(h, ".")
		h = strings.TrimPrefix(h, "*.")
		if h == "" || strings.ContainsAny(h, "* ") {
			continue
		}
		if (h == root || strings.HasSuffix(h, "."+root)) && domainRe.MatchString(h) {
			out = append(out, h)
		}
	}
	return out
}

// --- sources -------------------------------------------------------------

func srcCertspotter(ctx context.Context, root string) ([]string, error) {
	url := "https://api.certspotter.com/v1/issuances?domain=" + root + "&include_subdomains=true&expand=dns_names"
	body, status, err := httpGetRetry(ctx, dataClient, url, 2)
	if err != nil {
		return nil, err
	}
	if status == 429 {
		return nil, fmt.Errorf("rate limited (429)")
	}
	if status != 200 {
		return nil, fmt.Errorf("status %d", status)
	}
	var items []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	var out []string
	for _, it := range items {
		out = append(out, it.DNSNames...)
	}
	return out, nil
}

func srcCrtsh(ctx context.Context, root string) ([]string, error) {
	url := "https://crt.sh/?q=%25." + root + "&output=json"
	// crt.sh is frequently slow/unstable; cap it hard so it can't stall the run.
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	body, status, err := httpGet(cctx, dataClient, url, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("status %d", status)
	}
	var items []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, err
	}
	var out []string
	for _, it := range items {
		out = append(out, strings.Split(it.NameValue, "\n")...)
		if it.CommonName != "" {
			out = append(out, it.CommonName)
		}
	}
	return out, nil
}

func srcHackertarget(ctx context.Context, root string) ([]string, error) {
	url := "https://api.hackertarget.com/hostsearch/?q=" + root
	body, status, err := httpGet(ctx, dataClient, url, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("status %d", status)
	}
	text := string(body)
	if strings.Contains(text, "API count exceeded") || strings.Contains(strings.ToLower(text), "error check your search parameter") {
		return nil, fmt.Errorf("rate limited or bad query")
	}
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.Index(line, ","); i >= 0 {
			out = append(out, line[:i])
		}
	}
	return out, nil
}

func srcRapiddns(ctx context.Context, root string) ([]string, error) {
	url := "https://rapiddns.io/subdomain/" + root + "?full=1"
	body, status, err := httpGet(ctx, dataClient, url, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("status %d", status)
	}
	return hostExtractRe.FindAllString(string(body), -1), nil
}

func srcOTX(ctx context.Context, root string) ([]string, error) {
	url := "https://otx.alienvault.com/api/v1/indicators/domain/" + root + "/passive_dns"
	body, status, err := httpGet(ctx, dataClient, url, nil)
	if err != nil {
		return nil, err
	}
	if status == 429 {
		return nil, fmt.Errorf("rate limited (429)")
	}
	if status != 200 {
		return nil, fmt.Errorf("status %d", status)
	}
	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, err
	}
	var out []string
	for _, p := range data.PassiveDNS {
		out = append(out, p.Hostname)
	}
	return out, nil
}
