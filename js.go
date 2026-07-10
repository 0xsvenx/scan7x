package main

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// endpointRe captures quoted absolute URLs and paths embedded in JS/text.
// The quote class covers single, double and backtick (\x60) string delimiters.
var endpointRe = regexp.MustCompile("[\"'\\x60]((?:https?:)?//[^\"'\\x60\\s]{4,}|/[a-zA-Z0-9_][^\"'\\x60\\s]{1,})[\"'\\x60]")

// downloadAndExtract fetches each JS URL, saves unique bodies to jsDir, and
// returns the saved file paths plus all endpoints discovered inside them.
func downloadAndExtract(ctx context.Context, jsURLs []string, jsDir string, threads int) (downloaded []string, endpoints []string) {
	if threads < 1 {
		threads = 1
	}
	_ = os.MkdirAll(jsDir, 0o755)

	in := make(chan string)
	type result struct {
		path      string
		endpoints []string
	}
	out := make(chan result)
	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]bool{}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range in {
				body, status, err := httpGet(ctx, probeClient, u, nil)
				if err != nil || status != 200 || len(body) == 0 {
					continue
				}
				sum := sha1.Sum(body)
				h := hex.EncodeToString(sum[:])
				mu.Lock()
				dup := seen[h]
				seen[h] = true
				mu.Unlock()
				if dup {
					continue
				}
				name := sanitizeFilename(u)
				if !strings.HasSuffix(strings.ToLower(name), ".js") {
					name += ".js"
				}
				full := filepath.Join(jsDir, h[:8]+"_"+name)
				if err := os.WriteFile(full, body, 0o644); err != nil {
					continue
				}
				out <- result{path: full, endpoints: extractEndpoints(body)}
			}
		}()
	}
	go func() {
		defer close(in)
		for _, u := range jsURLs {
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

	var all []string
	for r := range out {
		downloaded = append(downloaded, r.path)
		all = append(all, r.endpoints...)
	}
	return downloaded, dedupSorted(all)
}

func extractEndpoints(body []byte) []string {
	var out []string
	for _, m := range endpointRe.FindAllSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		if e := strings.TrimSpace(string(m[1])); validEndpoint(e) {
			out = append(out, e)
		}
	}
	return out
}

// validEndpoint drops obvious regex noise (escape artifacts, minified blobs)
// while keeping real absolute URLs and paths.
func validEndpoint(e string) bool {
	if len(e) < 2 || e == "//" {
		return false
	}
	if strings.ContainsAny(e, "\\ \t\n\r") {
		return false
	}
	if strings.HasPrefix(e, "//") {
		// protocol-relative: require a dotted host or an inner path slash,
		// otherwise it is almost always a base64/minified fragment.
		rest := e[2:]
		if !strings.Contains(rest, ".") && !strings.Contains(rest, "/") {
			return false
		}
	}
	return true
}
