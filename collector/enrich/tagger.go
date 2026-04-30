// Package enrich adds heuristic tags, severity, and (optionally) LLM-derived
// summaries to a normalize.Item.
package enrich

import (
	"regexp"
	"strings"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

// VendorList is the user-configured list of vendors to highlight (tagged & boosted).
type VendorList []string

// TagList is the user-configured list of tag keywords to highlight.
type TagList []string

// cveRE captures CVE identifiers anywhere in the text.
var cveRE = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// vendorPatterns is a static dictionary of common vendor mentions in security
// news. It complements the user-supplied VendorList by recognising vendors
// even when the user hasn't whitelisted them in config.
var vendorPatterns = map[string][]string{
	"microsoft":   {"microsoft", "windows", "azure", "exchange server", "outlook"},
	"cisco":       {"cisco"},
	"fortinet":    {"fortinet", "fortigate", "fortios"},
	"paloalto":    {"palo alto", "pan-os"},
	"citrix":      {"citrix", "netscaler"},
	"vmware":      {"vmware"},
	"ivanti":      {"ivanti", "pulse secure"},
	"apache":      {"apache "},
	"openssl":     {"openssl"},
	"linux":       {"linux kernel"},
	"chrome":      {"chrome", "chromium"},
	"firefox":     {"firefox", "mozilla"},
	"wordpress":   {"wordpress", "wp plugin"},
	"jenkins":     {"jenkins"},
	"confluence":  {"confluence"},
	"oracle":      {"oracle"},
	"sap":         {"sap"},
	"adobe":       {"adobe", "acrobat", "reader"},
	"mongodb":     {"mongodb"},
	"postgres":    {"postgresql", "postgres"},
	"github":      {"github"},
	"gitlab":      {"gitlab"},
	"docker":      {"docker"},
	"kubernetes":  {"kubernetes", "k8s"},
}

// classKeywords maps free-form text patterns to attack-class tags.
var classKeywords = []struct {
	tag      string
	patterns []string
}{
	{"rce", []string{"remote code execution", "rce ", "arbitrary code execution", "code execution vuln"}},
	{"auth-bypass", []string{"authentication bypass", "auth bypass", "unauthenticated access"}},
	{"lpe", []string{"privilege escalation", "local privilege escalation"}},
	{"sqli", []string{"sql injection"}},
	{"xss", []string{"cross-site scripting", "stored xss", "reflected xss"}},
	{"path-traversal", []string{"path traversal", "directory traversal"}},
	{"actively-exploited", []string{"actively exploited", "in the wild", "exploited in the wild"}},
	{"0day", []string{"zero-day", "0-day", "0day"}},
	{"ransomware", []string{"ransomware", "lockbit", "blackcat", "alphv", "clop"}},
	{"breach", []string{"data breach", "data leak", "exposed records", "compromised database"}},
	{"supply-chain", []string{"supply chain attack", "supply-chain compromise"}},
	{"phishing", []string{"phishing campaign", "spear phishing", "phishing kit"}},
	{"malware", []string{"malware", "trojan", "infostealer"}},
}

// Tag inspects an item's title + summary and appends the matching tags / vendors.
// It does NOT remove existing tags (e.g. those passed in from sources.Hints).
func Tag(it *normalize.Item, vendors VendorList) {
	text := strings.ToLower(it.Title + " " + it.Summary)

	for _, m := range cveRE.FindAllString(it.Title+" "+it.Summary, -1) {
		it.CVEs = appendUniqueUpper(it.CVEs, m)
	}

	for vendor, patterns := range vendorPatterns {
		for _, p := range patterns {
			if strings.Contains(text, p) {
				it.Vendors = appendUnique(it.Vendors, vendor)
				it.Tags = appendUnique(it.Tags, vendor)
				break
			}
		}
	}

	for _, watched := range vendors {
		w := strings.ToLower(watched)
		for _, v := range it.Vendors {
			if v == w {
				it.Tags = appendUnique(it.Tags, "watch")
				break
			}
		}
	}

	for _, c := range classKeywords {
		for _, p := range c.patterns {
			if strings.Contains(text, p) {
				it.Tags = appendUnique(it.Tags, c.tag)
				break
			}
		}
	}
}

func appendUnique(ss []string, s string) []string {
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}

func appendUniqueUpper(ss []string, s string) []string {
	s = strings.ToUpper(s)
	for _, x := range ss {
		if x == s {
			return ss
		}
	}
	return append(ss, s)
}
