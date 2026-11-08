package sources

import (
	"regexp"
	"strings"
)

// Attack is the exploitation precondition triple shown on vulnerability
// cards. Values follow CVSS letters:
//
//	AV: N network, A adjacent, L local, P physical
//	PR: N none, L low, H high
//	UI: N none, R required ("" when unknown)
type Attack struct {
	AV string `json:"av"`
	PR string `json:"pr"`
	UI string `json:"ui,omitempty"`
}

// VulnFacts are structured fields some vulnerability sources provide.
type VulnFacts struct {
	Product string
	Impact  string // short key: rce, lpe, info, dos, auth-bypass, ssrf, xss, ...
	CWEs    []string
	Attack  *Attack
}

var validLetters = map[string]map[string]bool{
	"AV": {"N": true, "A": true, "L": true, "P": true},
	"PR": {"N": true, "L": true, "H": true},
	"UI": {"N": true, "R": true},
}

// ParseCVSSVector reads AV / PR / UI from a CVSS v2, v3.x or v4.0 vector.
// It returns nil when the vector is missing or malformed.
func ParseCVSSVector(v string) *Attack {
	parts := map[string]string{}
	for _, kv := range strings.Split(v, "/") {
		k, val, ok := strings.Cut(kv, ":")
		if ok {
			parts[k] = val
		}
	}
	a := &Attack{AV: parts["AV"], PR: parts["PR"], UI: parts["UI"]}
	if a.PR == "" { // CVSS v2 has Au instead of PR
		switch parts["Au"] {
		case "N":
			a.PR = "N"
		case "S", "M":
			a.PR = "L"
		}
	}
	switch a.UI { // CVSS v4: P(assive) / A(ctive) both need a user
	case "P", "A":
		a.UI = "R"
	}
	if !validLetters["AV"][a.AV] || !validLetters["PR"][a.PR] {
		return nil
	}
	if a.UI != "" && !validLetters["UI"][a.UI] {
		return nil
	}
	return a
}

// zdiImpacts maps the impact phrase that ends a ZDI title to a short key.
// Longer phrases first so "Local Privilege Escalation" wins over
// "Privilege Escalation".
var zdiImpacts = []struct{ phrase, key string }{
	{"Remote Code Execution", "rce"},
	{"Local Privilege Escalation", "lpe"},
	{"Privilege Escalation", "lpe"},
	{"Information Disclosure", "info"},
	{"Denial-of-Service", "dos"},
	{"Authentication Bypass", "auth-bypass"},
	{"Security Feature Bypass", "feature-bypass"},
	{"Server-Side Request Forgery", "ssrf"},
	{"Cross-Site Scripting", "xss"},
	{"Arbitrary File Deletion", "file-delete"},
	{"Arbitrary File Creation", "file-write"},
	{"Arbitrary File Write", "file-write"},
	{"Arbitrary File Read", "file-read"},
	{"Restricted File Write", "file-write"},
	{"Directory Traversal", "path-traversal"},
	{"SQL Injection", "sqli"},
	{"Command Injection", "command-injection"},
}

// zdiRootCauses maps root-cause phrases in ZDI titles to CWE IDs.
var zdiRootCauses = []struct{ phrase, cwe string }{
	{"Heap-based Buffer Overflow", "CWE-122"},
	{"Stack-based Buffer Overflow", "CWE-121"},
	{"Out-Of-Bounds Write", "CWE-787"},
	{"Out-Of-Bounds Read", "CWE-125"},
	{"Use-After-Free", "CWE-416"},
	{"Double Free", "CWE-415"},
	{"Type Confusion", "CWE-843"},
	{"Integer Overflow", "CWE-190"},
	{"Integer Underflow", "CWE-191"},
	{"Buffer Overflow", "CWE-120"},
	{"Memory Corruption", "CWE-119"},
	{"Uninitialized Variable", "CWE-457"},
	{"Uninitialized Memory", "CWE-908"},
	{"NULL Pointer Dereference", "CWE-476"},
	{"SQL Injection", "CWE-89"},
	{"OS Command Injection", "CWE-78"},
	{"Command Injection", "CWE-77"},
	{"Code Injection", "CWE-94"},
	{"Deserialization of Untrusted Data", "CWE-502"},
	{"Directory Traversal", "CWE-22"},
	{"Link Following", "CWE-59"},
	{"Cleartext Storage of Credentials", "CWE-256"},
	{"Hard-coded Credentials", "CWE-798"},
	{"Missing Authentication", "CWE-306"},
	{"Improper Authentication", "CWE-287"},
	{"Incorrect Permission Assignment", "CWE-732"},
	{"Uncontrolled Search Path", "CWE-427"},
	{"Exposed Dangerous Method", "CWE-749"},
	{"XML External Entity Processing", "CWE-611"},
	{"Server-Side Request Forgery", "CWE-918"},
	{"Cross-Site Scripting", "CWE-79"},
	{"Improper Certificate Validation", "CWE-295"},
	{"Race Condition", "CWE-362"},
	{"Inclusion of Functionality from Untrusted Control Sphere", "CWE-829"},
	{"Protection Mechanism Failure", "CWE-693"},
	{"Argument Injection", "CWE-88"},
	{"Numeric Truncation Error", "CWE-197"},
	{"Improper Handling Of Error Condition", "CWE-755"},
	{"Server-Side Template Injection", "CWE-1336"},
	{"Hardcoded Encyption Key", "CWE-321"},
	{"Hard-coded Cryptographic Key", "CWE-321"},
	{"External Control of File Path", "CWE-73"},
	{"Incorrect Authorization", "CWE-863"},
	{"Missing Authorization", "CWE-862"},
	{"Exposed Dangerous Function", "CWE-749"},
	{"Path Traversal", "CWE-22"},
	{"Cleartext Storage", "CWE-312"},
	{"Time-Of-Check Time-Of-Use", "CWE-367"},
}

var (
	zdiTitleRE = regexp.MustCompile(`^ZDI-\d{2}-\d+:\s*(.+?)\s+Vulnerability\s*$`)
	zdiTagRE   = regexp.MustCompile(`^(?:\((?:0Day|Pwn2Own)\)\s*)+`)
)

// ZDIFacts parses a ZDI advisory title ("ZDI-26-833: <product> <component>
// <root cause> <impact> Vulnerability") and its templated summary.
func ZDIFacts(title, summary string) VulnFacts {
	var f VulnFacts
	m := zdiTitleRE.FindStringSubmatch(strings.TrimSpace(title))
	if m == nil {
		return f
	}
	rest := zdiTagRE.ReplaceAllString(m[1], "")
	for _, im := range zdiImpacts {
		if r, ok := cutSuffixFold(rest, im.phrase); ok {
			f.Impact, rest = im.key, r
			break
		}
	}
	for _, rc := range zdiRootCauses {
		if r, ok := cutSuffixFold(rest, rc.phrase); ok {
			f.CWEs, rest = []string{rc.cwe}, r
			break
		}
	}
	// An impact phrase that is also a root cause (SSRF, SQLi) names the CWE.
	if f.CWEs == nil {
		for _, rc := range zdiRootCauses {
			if _, ok := cutSuffixFold(m[1], rc.phrase); ok {
				f.CWEs = []string{rc.cwe}
				break
			}
		}
	}
	f.Product = strings.TrimSpace(rest)
	f.Attack = zdiAttack(summary)
	return f
}

func zdiAttack(summary string) *Attack {
	s := strings.ToLower(summary)
	a := &Attack{}
	switch {
	case strings.Contains(s, "allows network-adjacent attackers"):
		a.AV = "A"
	case strings.Contains(s, "allows remote attackers"):
		a.AV = "N"
	case strings.Contains(s, "allows local attackers"):
		a.AV = "L"
	case strings.Contains(s, "allows physically present attackers"):
		a.AV = "P"
	default:
		return nil
	}
	// ZDI omits the authentication sentence when user interaction is
	// required; PR then stays unknown rather than guessed.
	switch {
	case strings.Contains(s, "authentication is not required"):
		a.PR = "N"
	case strings.Contains(s, "authentication is required"),
		strings.Contains(s, "must first obtain the ability to execute low-privileged code"):
		a.PR = "L"
	case strings.Contains(s, "user interaction is required"):
	default:
		return nil
	}
	if strings.Contains(s, "user interaction is required") {
		a.UI = "R"
	} else {
		a.UI = "N"
	}
	return a
}

// cutSuffixFold removes " "+suffix from s, ignoring case.
func cutSuffixFold(s, suffix string) (string, bool) {
	n := len(s) - len(suffix) - 1
	if n < 0 || s[n] != ' ' || !strings.EqualFold(s[n+1:], suffix) {
		return s, false
	}
	return s[:n], true
}

// kevProduct joins KEV's vendorProject and product without repeating the
// vendor ("WordPress" + "WordPress Core" -> "WordPress Core").
func kevProduct(vendor, product string) string {
	vendor, product = strings.TrimSpace(vendor), strings.TrimSpace(product)
	switch {
	case vendor == "":
		return product
	case product == "":
		return vendor
	case strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)):
		return product
	}
	return vendor + " " + product
}

var cweIDRE = regexp.MustCompile(`^CWE-\d{1,5}$`)

// pickCWEs collects distinct CWE IDs from NVD weaknesses, in order. The
// placeholders NVD-CWE-noinfo / NVD-CWE-Other are skipped.
func pickCWEs(ws []nvdWeakness) []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range ws {
		for _, d := range w.Description {
			v := strings.TrimSpace(d.Value)
			if cweIDRE.MatchString(v) && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}
