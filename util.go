package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	// domainRe matches a fully-qualified hostname (at least one dot, valid labels).
	domainRe = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$`)
	// hostExtractRe finds hostname-looking tokens inside arbitrary text (HTML, etc.).
	hostExtractRe = regexp.MustCompile(`(?i)[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+`)
	nonAlnumAll   = regexp.MustCompile(`[^a-z0-9]+`)
	slugRe        = regexp.MustCompile(`[^a-z0-9]+`)
	unsafeFnRe    = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)
)

// logf prints progress/diagnostics to stderr so stdout stays result-only.
func logf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// normalizeHost extracts a bare hostname from a scope identifier or URL.
// It returns the host, whether the identifier was a wildcard, and whether it
// resolved to a syntactically valid hostname.
func normalizeHost(id string) (host string, wildcard bool, ok bool) {
	s := strings.TrimSpace(strings.ToLower(id))
	if s == "" {
		return "", false, false
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && isAllDigits(s[i+1:]) {
		s = s[:i]
	}
	for {
		switch {
		case strings.HasPrefix(s, "*."):
			s = s[2:]
			wildcard = true
			continue
		case strings.HasPrefix(s, "*"):
			s = s[1:]
			wildcard = true
			continue
		case strings.HasPrefix(s, "."):
			s = s[1:]
			continue
		}
		break
	}
	s = strings.Trim(s, ".")
	if s == "" || strings.ContainsAny(s, "* ") {
		return "", wildcard, false
	}
	if !domainRe.MatchString(s) {
		return "", wildcard, false
	}
	return s, wildcard, true
}

func hostFromURL(raw string) string {
	h, _, ok := normalizeHost(raw)
	if !ok {
		return ""
	}
	return h
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isCIDR(s string) bool {
	_, _, err := net.ParseCIDR(strings.TrimSpace(s))
	return err == nil
}

// squash lowercases and strips every non-alphanumeric rune (for fuzzy matching).
func squash(s string) string {
	return nonAlnumAll.ReplaceAllString(strings.ToLower(s), "")
}

// slug produces a filesystem/URL-friendly identifier.
func slug(s string) string {
	s = slugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(s)), "-")
	return strings.Trim(s, "-")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func sanitizeFilename(s string) string {
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = unsafeFnRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_.")
	if len(s) > 120 {
		s = s[:120]
	}
	if s == "" {
		s = "file"
	}
	return s
}

func dedupSorted(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		k := strings.ToLower(s)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			return err
		}
	}
	return w.Flush()
}

func writeString(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func truncateList(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func truncateStr(s string, n int) string {
	if len(s) <= n || n <= 1 {
		return s
	}
	return s[:n-1] + "…"
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}
