package jatrans

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
)

func TestPlanSplitsKindsAndOrdersByScore(t *testing.T) {
	now := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	nvd := normalize.Item{ID: "nvd", Category: "vuln", Title: "[CVSS 9.8 CRITICAL] CVE-2026-11111 — Foo flaw", Summary: "Foo flaw.", Score: 50, Published: now}
	zdi := normalize.Item{ID: "zdi", Category: "vuln", Title: "ZDI-26-1: Bar RCE", Summary: "x", Score: 90, Product: "Bar", Published: now}
	news := normalize.Item{ID: "news", Category: "news", Title: "Hackers hit bank", Summary: "y", Score: 70, Published: now}
	old := normalize.Item{ID: "old", Category: "news", Title: "Older story", Summary: "z", Score: 70, Published: now.Add(-time.Hour)}
	ja := normalize.Item{ID: "ja", Category: "news", Title: "不正アクセス", Score: 99}

	tasks := Plan([]normalize.Item{nvd, zdi, old, news, ja}, Cache{})
	var got []string
	for _, tk := range tasks {
		got = append(got, tk.Item.ID+":"+string(tk.Kind))
	}
	want := "news:full old:full nvd:product"
	if strings.Join(got, " ") != want {
		t.Fatalf("plan = %v, want %s", got, want)
	}

	cached := Cache{"nvd": {Hash: SourceHash(nvd), Product: "Foo"}, "news": {Hash: SourceHash(news), Title: "訳"}}
	if tasks := Plan([]normalize.Item{nvd, news}, cached); len(tasks) != 0 {
		t.Fatalf("cached items planned again: %+v", tasks)
	}
}

func TestValidProduct(t *testing.T) {
	desc := "A vulnerability was detected in TOTOLINK CA300-PoE 6.2c.884. Affected is the function setWiFi."
	if !validProduct(desc, "TOTOLINK CA300-PoE") {
		t.Fatal("verbatim product rejected")
	}
	if validProduct(desc, "TP-Link Archer") {
		t.Fatal("product not in the text must be rejected")
	}
	if validProduct(desc, "") || validProduct(desc, strings.Repeat("A", 100)) {
		t.Fatal("empty or overlong product must be rejected")
	}
}

func TestBrandsKept(t *testing.T) {
	if !brandsKept("SonicWall warns of SSL-VPN MFA bypass", "SonicWall が SSL-VPN の MFA 回避を警告") {
		t.Fatal("kept brands rejected")
	}
	if brandsKept("SonicWall warns of SSL-VPN MFA bypass", "ソニーウォールが SSL-VPN の MFA 回避を警告") {
		t.Fatal("katakana brand must be rejected")
	}
	if brandsKept("Cisco patches IOS XE flaw", "シスコが IOS XE の欠陥を修正") {
		t.Fatal("known vendor in katakana must be rejected")
	}
	if !brandsKept("Hackers steal money from a bank", "ハッカーが銀行から資金を盗んだ") {
		t.Fatal("title without brands must pass")
	}
}

func TestRunExtractsProduct(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		content := `{"product":"TOTOLINK CA300-PoE"}`
		if !strings.Contains(string(body), "Extract the affected product") {
			content = `{"items":[]}`
		}
		resp := map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": content}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	it := normalize.Item{ID: "n", Category: "vuln", Title: "[CVSS 9.1 CRITICAL] CVE-2026-12345 — x",
		Summary: "A vulnerability was detected in TOTOLINK CA300-PoE 6.2c.884."}
	c := Client{Endpoint: srv.URL, HTTP: srv.Client()}
	got, st := c.Run(context.Background(), Plan([]normalize.Item{it}, Cache{}))
	if st.Translated != 1 || got["n"].Product != "TOTOLINK CA300-PoE" || got["n"].Title != "" {
		t.Fatalf("got %+v stats %+v", got, st)
	}
	applied := Apply([]normalize.Item{it}, got)
	if applied[0].Product != "TOTOLINK CA300-PoE" || applied[0].TitleJa != "" {
		t.Fatalf("applied %+v", applied[0])
	}
}

func TestVendorsKeptInSummary(t *testing.T) {
	if vendorsKept("Cisco Talos observed a new C2", "シスコ・タルスが新しい C2 を観測") {
		t.Fatal("katakana vendor in summary must be rejected")
	}
	if !vendorsKept("Cisco Talos observed a new C2", "Cisco Talos が新しい C2 を観測") {
		t.Fatal("kept vendor rejected")
	}
}

func TestBrandsKeptIgnoresDottedAbbreviations(t *testing.T) {
	if !brandsKept("U.S. charges hackers", "米国がハッカーを起訴") {
		t.Fatal("U.S. must not be required verbatim")
	}
}

func TestValidProductRejectsCommonWords(t *testing.T) {
	desc := "A flaw in OpenAM allows an attacker to bypass checks."
	for _, p := range []string{"in", "an attacker", "allows", "flaw"} {
		if validProduct(desc, p) {
			t.Errorf("%q must be rejected", p)
		}
	}
	if !validProduct(desc, "OpenAM") {
		t.Error("OpenAM rejected")
	}
	if validProduct("Uses OpenAMX internally", "OpenAM") {
		t.Error("substring inside a longer word must be rejected")
	}
}

func TestRejectedProductIsNotRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{"choices": []any{map[string]any{"message": map[string]any{"content": `{"product":""}`}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	it := normalize.Item{ID: "n", Category: "vuln", Title: "[CVSS 9.1 CRITICAL] CVE-2026-12345 — x", Summary: "A flaw allows code execution."}
	c := Client{Endpoint: srv.URL, HTTP: srv.Client()}
	got, st := c.Run(context.Background(), Plan([]normalize.Item{it}, Cache{}))
	if st.Rejected != 1 || !got["n"].Tried {
		t.Fatalf("got %+v stats %+v", got, st)
	}
	if tasks := Plan([]normalize.Item{it}, got); len(tasks) != 0 {
		t.Fatalf("tried item planned again: %+v", tasks)
	}
}
