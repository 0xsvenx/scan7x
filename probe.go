package main

import (
	"context"
	"html"
	"regexp"
	"strings"
	"sync"
)

// LiveHost is a host that answered an HTTP(S) request.
type LiveHost struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Title  string `json:"title"`
}

var (
	titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	wsRe    = regexp.MustCompile(`\s+`)
)

// probeHosts checks each host over https then http and returns the live ones.
func probeHosts(ctx context.Context, hosts []string, threads int) []LiveHost {
	if threads < 1 {
		threads = 1
	}
	in := make(chan string)
	out := make(chan LiveHost)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range in {
				if lh, ok := probeOne(ctx, h); ok {
					out <- lh
				}
			}
		}()
	}
	go func() {
		defer close(in)
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				return
			case in <- h:
			}
		}
	}()
	go func() {
		wg.Wait()
		close(out)
	}()
	var results []LiveHost
	for lh := range out {
		results = append(results, lh)
	}
	return results
}

func probeOne(ctx context.Context, host string) (LiveHost, bool) {
	for _, scheme := range []string{"https://", "http://"} {
		u := scheme + host
		body, status, err := httpGet(ctx, probeClient, u, nil)
		if err != nil {
			continue
		}
		return LiveHost{URL: u, Status: status, Title: extractTitle(body)}, true
	}
	return LiveHost{}, false
}

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := wsRe.ReplaceAllString(string(m[1]), " ")
	t = strings.TrimSpace(html.UnescapeString(t))
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}
