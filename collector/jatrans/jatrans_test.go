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

func TestTranslateStopsOnNonJSONResponse(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("OK"))
	}))
	defer srv.Close()
	c := Client{Endpoint: srv.URL, Token: "tok", HTTP: srv.Client(), BatchSize: 1, MaxRequests: 10}
	_, st := c.Translate(context.Background(), []normalize.Item{item("a", "one", ""), item("b", "two", "")})
	if calls != 1 || st.Err == nil || !strings.Contains(st.Err.Error(), `"OK"`) {
		t.Fatalf("calls=%d err=%v", calls, st.Err)
	}
}

func TestTranslateStopsWhenBudgetRunsOut(t *testing.T) {
	var calls int32
	srv := fakeModels(t, &calls, http.StatusOK)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	c := Client{Endpoint: srv.URL, Token: "tok", HTTP: srv.Client(), BatchSize: 1}
	got, st := c.Translate(ctx, []normalize.Item{item("a", "one", ""), item("b", "two", "")})
	if len(got) != 0 || !IsBudgetExhausted(st.Err) || st.Remaining != 1 {
		t.Fatalf("got=%v stats=%+v", got, st)
	}
}

func TestTranslateStopsWhenServerUnreachable(t *testing.T) {
	c := Client{Endpoint: "http://127.0.0.1:1/v1/chat/completions", HTTP: http.DefaultClient, BatchSize: 1}
	_, st := c.Translate(context.Background(), []normalize.Item{item("a", "one", ""), item("b", "two", "")})
	if st.Requests != 1 || st.Err == nil || IsBudgetExhausted(st.Err) {
		t.Fatalf("stats=%+v", st)
	}
}

func TestTitleDerivedFromSummaryWhenTitleRepeatsIt(t *testing.T) {
	var calls int32
	srv := fakeModels(t, &calls, http.StatusOK)
	defer srv.Close()
	c := Client{Endpoint: srv.URL, Token: "tok", HTTP: srv.Client(), BatchSize: 4}
	it := item("n", "[CVSS 9.8 CRITICAL] CVE-2026-12345 — imgproxy has an integer overflow in…",
		"imgproxy has an integer overflow in ICO.")
	got, st := c.Translate(context.Background(), []normalize.Item{it})
	if st.Translated != 1 {
		t.Fatalf("stats = %+v", st)
	}
	// The fake echoes "訳:"+text; the title must come from the summary.
	want := "[CVSS 9.8 CRITICAL] CVE-2026-12345 — 訳:imgproxy has an integer overflow in ICO."
	if got["n"].Title != want {
		t.Fatalf("title = %q", got["n"].Title)
	}
}

func TestHeadline(t *testing.T) {
	if got := headline("最初の文です。次の文。"); got != "最初の文です。" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("あ", 200)
	if got := headline(long); len([]rune(got)) != headlineMax+1 || !strings.HasSuffix(got, "…") {
		t.Fatalf("got %q", got)
	}
}

func TestSameItemRejectsSwappedTranslation(t *testing.T) {
	src := "OpenAM before 16.1.4 contains an authentication bypass in the SAML v2.0 service provider."
	if !sameItem(src, "OpenAM 16.1.4 より前の SAML v2.0 サービスプロバイダーに認証回避がある。") {
		t.Fatal("matching translation rejected")
	}
	if sameItem(src, "Vikunja 2.7.1 より前に page=0 によるリソース消費の問題がある。") {
		t.Fatal("translation of a different item must be rejected")
	}
	if !sameItem("Hackers steal money from a bank", "ハッカーが銀行から資金を盗んだ") {
		t.Fatal("text without identifiers cannot be checked and must pass")
	}
}

func TestBatchEntryAcceptsNumericID(t *testing.T) {
	var p batchPayload
	if err := json.Unmarshal([]byte(`{"items":[{"id":0,"title":"a","summary":""},{"id":"1","title":"b"}]}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.Items[0].ID != "0" || p.Items[1].ID != "1" {
		t.Fatalf("ids = %q %q", p.Items[0].ID, p.Items[1].ID)
	}
}

func TestSummaryAnsweredInTitleFieldIsAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `\"title\":\"\"`) {
			t.Errorf("empty title must not be sent: %s", body)
		}
		content := `{"items":[{"id":"0","title":"imgproxy に整数オーバーフローがある。"}]}`
		resp := map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	c := Client{Endpoint: srv.URL, HTTP: srv.Client(), BatchSize: 1}
	it := item("n", "[CVSS 9.8 CRITICAL] CVE-2026-12345 — imgproxy has an integer overflow in…",
		"imgproxy has an integer overflow in ICO.")
	got, st := c.Translate(context.Background(), []normalize.Item{it})
	if st.Translated != 1 || got["n"].Summary != "imgproxy に整数オーバーフローがある。" ||
		got["n"].Title != "[CVSS 9.8 CRITICAL] CVE-2026-12345 — imgproxy に整数オーバーフローがある。" {
		t.Fatalf("got %+v stats %+v", got["n"], st)
	}
}
