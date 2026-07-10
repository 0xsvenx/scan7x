package main

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// waybackURLs pulls known URLs for a target from the Wayback Machine CDX API.
// When includeSubs is true it queries *.target as well.
func waybackURLs(ctx context.Context, target string, includeSubs bool, limit int) ([]string, error) {
	prefix := target + "/*"
	if includeSubs {
		prefix = "*." + target + "/*"
	}
	u := "https://web.archive.org/cdx/search/cdx?url=" + prefix + "&output=text&fl=original&collapse=urlkey"
	if limit > 0 {
		u += fmt.Sprintf("&limit=%d", limit)
	}
	// The CDX API can be slow for heavily-archived domains; give it room but
	// still bound it so a single slow target can't stall the whole run.
	wctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	body, status, err := httpGetRetry(wctx, longClient, u, 1)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("status %d", status)
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

// collectURLs gathers Wayback URLs for wildcard roots (with subdomains) and for
// explicit known hosts.
func collectURLs(ctx context.Context, roots, known []string, limit int) []string {
	var all []string
	for i, r := range roots {
		select {
		case <-ctx.Done():
			return dedupSorted(all)
		default:
		}
		logf("  [urls %d/%d] wayback *.%s", i+1, len(roots), r)
		urls, err := waybackURLs(ctx, r, true, limit)
		if err != nil {
			logf("      wayback error: %v", err)
			continue
		}
		logf("      -> %d urls", len(urls))
		all = append(all, urls...)
	}
	for _, h := range known {
		select {
		case <-ctx.Done():
			return dedupSorted(all)
		default:
		}
		if urls, err := waybackURLs(ctx, h, false, limit); err == nil {
			all = append(all, urls...)
		}
	}
	return dedupSorted(all)
}

func isJSURL(u string) bool {
	p := u
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.ToLower(p)
	return strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs")
}

func filterJSURLs(urls []string) []string {
	var out []string
	for _, u := range urls {
		if isJSURL(u) {
			out = append(out, u)
		}
	}
	return dedupSorted(out)
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']?([^"'>\s]+)`)

// crawlScripts fetches each live base URL and extracts <script src> targets,
// resolved to absolute URLs.
func crawlScripts(ctx context.Context, liveURLs []string, threads int) []string {
	if threads < 1 {
		threads = 1
	}
	in := make(chan string)
	out := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for base := range in {
				body, status, err := httpGet(ctx, probeClient, base, nil)
				if err != nil || status >= 400 {
					continue
				}
				baseURL, perr := url.Parse(base)
				if perr != nil {
					continue
				}
				for _, m := range scriptSrcRe.FindAllStringSubmatch(string(body), -1) {
					ref := strings.TrimSpace(m[1])
					if ref == "" {
						continue
					}
					if ru, e := url.Parse(ref); e == nil {
						out <- baseURL.ResolveReference(ru).String()
					}
				}
			}
		}()
	}
	go func() {
		defer close(in)
		for _, u := range liveURLs {
			select {
			case <-ctx.Done():
				return
			case in <- u:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()
	var results []string
	for u := range out {
		results = append(results, u)
	}
	return dedupSorted(results)
}
