package epss

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

func fakeServer(t *testing.T, calls *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if ua := r.Header.Get("User-Agent"); ua != "test-ua" {
			t.Errorf("user agent = %q", ua)
		}
		var rows []string
		for _, c := range strings.Split(r.URL.Query().Get("cve"), ",") {
			rows = append(rows, `{"cve":"`+c+`","epss":"0.250000000","percentile":"0.900000000"}`)
		}
		_, _ = w.Write([]byte(`{"status":"OK","data":[` + strings.Join(rows, ",") + `]}`))
	}))
}

func TestLookupBatchesAndParses(t *testing.T) {
	var calls int32
	srv := fakeServer(t, &calls)
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client(), UserAgent: "test-ua", BatchSize: 2}
	got, err := c.Lookup(context.Background(), []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0001"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if len(got) != 3 || got["CVE-2026-0003"].Probability != 0.25 || got["CVE-2026-0003"].Percentile != 0.9 {
		t.Fatalf("got %+v", got)
	}
}

func TestLookupRejectsMalformedIDs(t *testing.T) {
	var calls int32
	srv := fakeServer(t, &calls)
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client(), UserAgent: "test-ua"}
	got, err := c.Lookup(context.Background(), []string{"CVE-2026-0001&x=1", "not-a-cve", "cve-2026-12345"})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(got) != 1 {
		t.Fatalf("calls=%d got=%+v", calls, got)
	}
	if _, ok := got["CVE-2026-12345"]; !ok {
		t.Fatalf("lower-case id not normalised: %+v", got)
	}
}

func TestLookupEmptyMakesNoRequest(t *testing.T) {
	var calls int32
	srv := fakeServer(t, &calls)
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client()}
	got, err := c.Lookup(context.Background(), nil)
	if err != nil || len(got) != 0 || calls != 0 {
		t.Fatalf("err=%v got=%v calls=%d", err, got, calls)
	}
}

func TestLookupHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if _, err := c.Lookup(context.Background(), []string{"CVE-2026-0001"}); err == nil {
		t.Fatal("want error on 429")
	}
}

func TestApplyTakesHighestAndCopies(t *testing.T) {
	items := []normalize.Item{
		{ID: "a", CVEs: []string{"CVE-1", "CVE-2"}},
		{ID: "b"},
	}
	scores := map[string]Score{"CVE-1": {0.1, 0.5}, "CVE-2": {0.7, 0.99}}
	got := Apply(items, scores)
	if got[0].EPSS != 0.7 || got[0].EPSSPercentile != 0.99 || got[1].EPSS != 0 {
		t.Fatalf("got %+v", got)
	}
	if items[0].EPSS != 0 {
		t.Fatal("input mutated")
	}
}

func TestCollectCVEs(t *testing.T) {
	items := []normalize.Item{{CVEs: []string{"CVE-1", "CVE-2"}}, {CVEs: []string{"CVE-2"}}}
	if got := CollectCVEs(items); len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}
