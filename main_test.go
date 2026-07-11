package main

import (
	"bufio"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantWild bool
		wantOK   bool
	}{
		{"*.example.com", "example.com", true, true},
		{"https://api.example.com/path?x=1", "api.example.com", false, true},
		{"http://data-api.coindesk.com/", "data-api.coindesk.com", false, true},
		{"example.com:8443", "example.com", false, true},
		{"*.*.example.com", "example.com", true, true},
		{"Fable 5", "", false, false},
		{"10.0.0.0/8", "", false, false},
		{"", "", false, false},
	}
	for _, c := range cases {
		host, wild, ok := normalizeHost(c.in)
		if host != c.wantHost || wild != c.wantWild || ok != c.wantOK {
			t.Errorf("normalizeHost(%q) = (%q,%v,%v), want (%q,%v,%v)",
				c.in, host, wild, ok, c.wantHost, c.wantWild, c.wantOK)
		}
	}
}

func TestCategorize(t *testing.T) {
	cases := []struct {
		rawType string
		id      string
		want    Category
	}{
		{"WILDCARD", "*.example.com", CatWildcard},
		{"OTHER", "*.artstation.com", CatWildcard}, // wildcard detected from "*"
		{"URL", "https://api.example.com/", CatAPI},
		{"URL", "https://www.example.com/", CatDomain},
		{"api", "https://foo.example.com", CatAPI},
		{"CIDR", "10.0.0.0/8", CatCIDR},
		{"GOOGLE_PLAY_APP_ID", "com.example.app", CatMobile},
		{"SOURCE_CODE", "https://github.com/x/y", CatSource},
		{"other", "https://gist.github.com/x", CatOther},
		{"AI_MODEL", "Fable 5", CatOther},
		{"web-application", "https://shop.example.com", CatDomain},
	}
	for _, c := range cases {
		if got := categorize(c.rawType, c.id); got != c.want {
			t.Errorf("categorize(%q,%q) = %q, want %q", c.rawType, c.id, got, c.want)
		}
	}
}

func TestValidEndpoint(t *testing.T) {
	good := []string{"/api/users", "//api.github.com/repos", "https://example.com/x", "/v1/graphql"}
	bad := []string{"//", "/", "//sQxAADgnABGiAAQBCqgCRMAAgEAH", `/404\`, "/a b", ""}
	for _, g := range good {
		if !validEndpoint(g) {
			t.Errorf("validEndpoint(%q) = false, want true", g)
		}
	}
	for _, b := range bad {
		if validEndpoint(b) {
			t.Errorf("validEndpoint(%q) = true, want false", b)
		}
	}
}

func TestExtractEndpoints(t *testing.T) {
	js := []byte(`var a="/api/v1/users";fetch('https://api.example.com/graphql');let b=` + "`" + `//cdn.example.com/x.js` + "`" + `;var junk="//AAAAAAAAAAAAAAAA";`)
	got := extractEndpoints(js)
	want := map[string]bool{
		"/api/v1/users":                   true,
		"https://api.example.com/graphql": true,
		"//cdn.example.com/x.js":          true,
	}
	for _, e := range got {
		if !want[e] {
			t.Errorf("unexpected endpoint extracted: %q", e)
		}
		delete(want, e)
	}
	if len(want) != 0 {
		t.Errorf("missing endpoints: %v", want)
	}
}

func TestFilterScopeHosts(t *testing.T) {
	in := []string{"www.example.com", "evil.com", "example.com", "*.example.com", "foo.bar", "API.EXAMPLE.COM"}
	got := dedupSorted(filterScopeHosts(in, "example.com"))
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("filterScopeHosts = %v, want %v", got, want)
	}
}

func TestIsJSURL(t *testing.T) {
	yes := []string{"https://x.com/a.js", "https://x.com/a.js?v=1", "https://x.com/a.min.js", "https://x.com/app.mjs"}
	no := []string{"https://x.com/a.css", "https://x.com/", "https://x.com/a.json"}
	for _, u := range yes {
		if !isJSURL(u) {
			t.Errorf("isJSURL(%q) = false, want true", u)
		}
	}
	for _, u := range no {
		if isJSURL(u) {
			t.Errorf("isJSURL(%q) = true, want false", u)
		}
	}
}

func TestSquashAndSlug(t *testing.T) {
	if squash("Red Bull") != "redbull" {
		t.Errorf("squash mismatch: %q", squash("Red Bull"))
	}
	if squash("red-bull!") != "redbull" {
		t.Errorf("squash mismatch: %q", squash("red-bull!"))
	}
	if slug("Red Bull GmbH") != "red-bull-gmbh" {
		t.Errorf("slug mismatch: %q", slug("Red Bull GmbH"))
	}
}

func TestIsQuit(t *testing.T) {
	for _, s := range []string{"exit", "quit", "q", "EXIT", "  Quit ", "Q"} {
		if !isQuit(s) {
			t.Errorf("isQuit(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"uber", "", "exitx", "quitter", "queue"} {
		if isQuit(s) {
			t.Errorf("isQuit(%q) = true, want false", s)
		}
	}
}

func TestPromptLine(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("uber\n"))
	if got := promptLine(r, "", "def"); got != "uber" {
		t.Errorf("promptLine typed = %q, want uber", got)
	}
	r = bufio.NewReader(strings.NewReader("\n"))
	if got := promptLine(r, "", "all"); got != "all" {
		t.Errorf("promptLine empty = %q, want default all", got)
	}
	r = bufio.NewReader(strings.NewReader("  spaced  \n"))
	if got := promptLine(r, "", "def"); got != "spaced" {
		t.Errorf("promptLine trim = %q, want spaced", got)
	}
}

func TestPromptYesNo(t *testing.T) {
	cases := []struct {
		in   string
		def  bool
		want bool
	}{
		{"y\n", false, true},
		{"yes\n", false, true},
		{"n\n", true, false},
		{"no\n", true, false},
		{"\n", true, true},
		{"\n", false, false},
	}
	for _, c := range cases {
		r := bufio.NewReader(strings.NewReader(c.in))
		if got := promptYesNo(r, "", c.def); got != c.want {
			t.Errorf("promptYesNo(%q, def=%v) = %v, want %v", c.in, c.def, got, c.want)
		}
	}
}

func TestResolveCategories(t *testing.T) {
	sel, err := resolveCategories("domains,apis")
	if err != nil {
		t.Fatal(err)
	}
	if !sel[CatDomain] || !sel[CatAPI] || sel[CatWildcard] {
		t.Errorf("resolveCategories selected wrong set: %v", sel)
	}
	if _, err := resolveCategories("bogus"); err == nil {
		t.Errorf("expected error for bogus category")
	}
}
