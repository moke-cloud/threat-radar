package jatrans

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

func item(id, title, summary string) normalize.Item {
	return normalize.Item{ID: id, Title: title, Summary: summary}
}

func TestNeedsTranslation(t *testing.T) {
	if !NeedsTranslation(item("a", "Valkey RCE", "")) {
		t.Fatal("english title should need translation")
	}
	if NeedsTranslation(item("b", "不正アクセス", "個人情報が流出")) {
		t.Fatal("japanese item should not")
	}
	if NeedsTranslation(item("c", "", "")) {
		t.Fatal("empty item should not")
	}
}

func TestSplitProtected(t *testing.T) {
	cases := map[string][2]string{
		"[CVSS 9.1 CRITICAL] CVE-2026-12345 — A flaw in X": {"[CVSS 9.1 CRITICAL] CVE-2026-12345 — ", "A flaw in X"},
		"ZDI-26-833: Valkey RCE":                           {"ZDI-26-833: ", "Valkey RCE"},
		"[KEV] CVE-2026-119977 — WordPress Core":           {"[KEV] CVE-2026-119977 — ", "WordPress Core"},
		"Plain title": {"", "Plain title"},
	}
	for in, want := range cases {
		keep, text := SplitProtected(in)
		if keep != want[0] || text != want[1] {
			t.Errorf("%q -> (%q, %q), want %v", in, keep, text, want)
		}
	}
}

func TestValidTranslation(t *testing.T) {
	src := "Flaw tracked as CVE-2026-1111 and CVE-2026-2222 in Foo."
	if !validTranslation(src, "Foo の CVE-2026-1111 と CVE-2026-2222 の脆弱性。") {
		t.Fatal("good translation rejected")
	}
	if validTranslation(src, "Foo の CVE-2026-1111 の脆弱性。") {
		t.Fatal("translation that drops a CVE must be rejected")
	}
	if validTranslation("Remote code execution", "Remote code execution") {
		t.Fatal("untranslated output must be rejected")
	}
	if validTranslation("short", strings.Repeat("あ", 2000)) {
		t.Fatal("runaway output must be rejected")
	}
}

func TestCacheApplyMissingPrune(t *testing.T) {
	a := item("a", "Valkey RCE", "remote code execution")
	b := item("b", "まとめ", "不正アクセス")
	c := item("c", "Exchange flaw", "")
	cache := Cache{
		"a":    {Hash: SourceHash(a), Title: "Valkey の RCE", Summary: "リモートコード実行"},
		"c":    {Hash: "stale", Title: "古い訳"},
		"gone": {Hash: "x", Title: "消える"},
	}
	missing := Missing([]normalize.Item{a, b, c}, cache)
	if len(missing) != 1 || missing[0].ID != "c" {
		t.Fatalf("missing = %+v", missing)
	}
	out := Apply([]normalize.Item{a, b, c}, cache)
	if out[0].TitleJa != "Valkey の RCE" || out[0].SummaryJa != "リモートコード実行" {
		t.Fatalf("apply a = %+v", out[0])
	}
	if out[2].TitleJa != "" {
		t.Fatal("stale hash must not be applied")
	}
	if a.TitleJa != "" {
		t.Fatal("Apply must not mutate its input")
	}
	pruned := Prune(cache, []normalize.Item{a, c})
	if _, ok := pruned["gone"]; ok || len(pruned) != 2 {
		t.Fatalf("pruned = %v", pruned)
	}
}

// fakeModels answers like the chat completions API: it echoes every input
// text back with a Japanese marker, keeping CVE IDs intact.
func fakeModels(t *testing.T, calls *int32, status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(calls, 1)
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("auth header = %q", got)
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var req chatRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("bad request: %v", err)
		}
		var in batchPayload
		if err := json.Unmarshal([]byte(req.Messages[1].Content), &in); err != nil {
			t.Fatalf("bad user payload: %v", err)
		}
		out := batchPayload{}
		for _, e := range in.Items {
			out.Items = append(out.Items, batchEntry{ID: e.ID, Title: "訳:" + e.Title, Summary: "訳:" + e.Summary})
		}
		content, _ := json.Marshal(out)
		resp := map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": string(content)}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestTranslateBatchesAndKeepsPrefix(t *testing.T) {
	var calls int32
	srv := fakeModels(t, &calls, http.StatusOK)
	defer srv.Close()
	c := Client{Endpoint: srv.URL, Token: "tok", Model: "m", HTTP: srv.Client(), BatchSize: 2, MaxRequests: 10}
	items := []normalize.Item{
		item("a", "[CVSS 9.8 CRITICAL] CVE-2026-12345 — Flaw in Foo", "Foo has CVE-2026-12345."),
		item("b", "Bar breach", ""),
		item("c", "Baz bug", "details"),
	}
	got, st := c.Translate(context.Background(), items)
	if calls != 2 {
		t.Fatalf("calls = %d, want 2 batches", calls)
	}
	if st.Translated != 3 || st.Err != nil {
		t.Fatalf("stats = %+v", st)
	}
	if got["a"].Title != "[CVSS 9.8 CRITICAL] CVE-2026-12345 — 訳:Flaw in Foo" {
		t.Fatalf("title a = %q", got["a"].Title)
	}
	if got["a"].Hash != SourceHash(items[0]) {
		t.Fatal("hash not recorded")
	}
	if got["b"].Summary != "" {
		t.Fatalf("empty summary should stay empty, got %q", got["b"].Summary)
	}
}

func TestTranslateStopsOnRateLimit(t *testing.T) {
	var calls int32
	srv := fakeModels(t, &calls, http.StatusTooManyRequests)
	defer srv.Close()
	c := Client{Endpoint: srv.URL, Token: "tok", Model: "m", HTTP: srv.Client(), BatchSize: 1, MaxRequests: 10}
	got, st := c.Translate(context.Background(), []normalize.Item{item("a", "x one", ""), item("b", "y two", "")})
	if calls != 1 || len(got) != 0 || st.Err == nil {
		t.Fatalf("calls=%d got=%v stats=%+v", calls, got, st)
	}
}

func TestTranslateRespectsMaxRequests(t *testing.T) {
	var calls int32
	srv := fakeModels(t, &calls, http.StatusOK)
	defer srv.Close()
	c := Client{Endpoint: srv.URL, Token: "tok", Model: "m", HTTP: srv.Client(), BatchSize: 1, MaxRequests: 2}
	items := []normalize.Item{item("a", "one", ""), item("b", "two", ""), item("c", "three", "")}
	got, st := c.Translate(context.Background(), items)
	if calls != 2 || len(got) != 2 || st.Remaining != 1 {
		t.Fatalf("calls=%d got=%d stats=%+v", calls, len(got), st)
	}
}
