package main

import (
	"regexp"
	"sort"
)

// Secret is an interesting string found inside a JS file (a possible leak).
type Secret struct {
	Type  string `json:"type"`
	Match string `json:"match"`
}

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

// secretPatterns are conservative regexes for high-signal credential formats.
// Some (generic_api_key, bearer) can produce false positives and are meant as
// leads to triage, not confirmed findings.
var secretPatterns = []secretPattern{
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"google_oauth_token", regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]{20,}`)},
	{"gcp_service_account", regexp.MustCompile(`"type"\s*:\s*"service_account"`)},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[0-9A-Za-z\-]{10,48}`)},
	{"slack_webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36,}`)},
	{"stripe_key", regexp.MustCompile(`(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{16,}`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}`)},
	{"private_key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"s3_bucket", regexp.MustCompile(`[a-z0-9.\-]{3,63}\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com`)},
	{"firebase_db", regexp.MustCompile(`[a-z0-9-]+\.firebaseio\.com`)},
	{"mailgun_key", regexp.MustCompile(`key-[0-9a-zA-Z]{32}`)},
	{"generic_secret", regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|client[_-]?secret|secret[_-]?key|access[_-]?token|auth[_-]?token)["'\s:=]{1,10}["'][A-Za-z0-9_\-]{16,64}["']`)},
}

// extractSecrets scans content for the known patterns and returns unique finds.
func extractSecrets(content []byte) []Secret {
	var out []Secret
	seen := map[string]bool{}
	for _, p := range secretPatterns {
		for _, m := range p.re.FindAll(content, -1) {
			s := string(m)
			if len(s) > 200 {
				s = s[:200]
			}
			key := p.name + "|" + s
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, Secret{Type: p.name, Match: s})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Match < out[j].Match
	})
	return out
}
