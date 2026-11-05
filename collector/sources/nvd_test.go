package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func nvdPage(start, total, per int) string {
	var vulns []string
	for i := start; i < start+per && i < total; i++ {
		vulns = append(vulns, fmt.Sprintf(`{"cve":{"id":"CVE-2026-%05d","published":"2026-11-04T10:00:00.000",
"descriptions":[{"lang":"en","value":"remote code execution in widget"}],
"metrics":{"cvssMetricV31":[{"type":"Secondary","cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}]}}}`, i))
	}
	return fmt.Sprintf(`{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"vulnerabilities":[%s]}`,
		per, start, total, strings.Join(vulns, ","))
}

func TestNVDUsesPublishWindowAndPages(t *testing.T) {
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		_, _ = w.Write([]byte(nvdPage(start, 5, 2)))
	}))
	defer srv.Close()
	n := NewNVD(Config{ID: "nvd", URL: srv.URL, Options: map[string]any{"results_per_page": 2}}, HTTPClientConfig{})
	n.pageDelay = 0
	items, err := n.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 5 || len(queries) != 3 {
		t.Fatalf("items=%d queries=%d", len(items), len(queries))
	}
	if !strings.Contains(queries[0], "pubStartDate=") || strings.Contains(queries[0], "lastMod") {
		t.Fatalf("query = %s", queries[0])
	}
	if !strings.HasPrefix(items[0].Title, "[CVSS 9.8 CRITICAL]") {
		t.Fatalf("title = %s", items[0].Title)
	}
}

func TestNVDStopsAtMaxPages(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		start, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
		_, _ = w.Write([]byte(nvdPage(start, 100, 2)))
	}))
	defer srv.Close()
	n := NewNVD(Config{ID: "nvd", URL: srv.URL, Options: map[string]any{"results_per_page": 2, "max_pages": 2}}, HTTPClientConfig{})
	n.pageDelay = 0
	items, err := n.Fetch(context.Background())
	if err != nil || calls != 2 || len(items) != 4 {
		t.Fatalf("err=%v calls=%d items=%d", err, calls, len(items))
	}
}

func TestNVDReturnsPartialOnLaterPageError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls > 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(nvdPage(0, 10, 2)))
	}))
	defer srv.Close()
	n := NewNVD(Config{ID: "nvd", URL: srv.URL, Options: map[string]any{"results_per_page": 2}}, HTTPClientConfig{})
	n.pageDelay = 0
	items, err := n.Fetch(context.Background())
	if err == nil || len(items) != 2 {
		t.Fatalf("want partial items with error: err=%v items=%d", err, len(items))
	}
}

func TestNVDFirstPageErrorFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	n := NewNVD(Config{ID: "nvd", URL: srv.URL}, HTTPClientConfig{})
	if _, err := n.Fetch(context.Background()); err == nil {
		t.Fatal("want error")
	}
}

func TestParseDateFormats(t *testing.T) {
	for _, s := range []string{
		"2026-10-29T15:43+09:00",
		"Wed, 04 Nov 2026 16:25:55 GMT",
		"2026-11-01T00:00:00Z",
		"2026-11-01T00:00:00.000-07:00",
		"Wed, 4 Nov 2026 16:25:55 +0000",
	} {
		if parseDate(s).IsZero() {
			t.Errorf("failed to parse %q", s)
		}
	}
}

func TestNVDMinCVSSFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"resultsPerPage":3,"startIndex":0,"totalResults":3,"vulnerabilities":[
{"cve":{"id":"CVE-2026-1","published":"2026-11-04T10:00:00.000","descriptions":[{"lang":"en","value":"a"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.1,"baseSeverity":"CRITICAL"}}]}}},
{"cve":{"id":"CVE-2026-2","published":"2026-11-04T10:00:00.000","descriptions":[{"lang":"en","value":"b"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM"}}]}}},
{"cve":{"id":"CVE-2026-3","published":"2026-11-04T10:00:00.000","descriptions":[{"lang":"en","value":"c"}]}}]}`))
	}))
	defer srv.Close()
	n := NewNVD(Config{ID: "nvd", URL: srv.URL, Options: map[string]any{"min_cvss": 8.0}}, HTTPClientConfig{})
	items, err := n.Fetch(context.Background())
	if err != nil || len(items) != 1 || items[0].CVEs[0] != "CVE-2026-1" {
		t.Fatalf("err=%v items=%+v", err, items)
	}
}
