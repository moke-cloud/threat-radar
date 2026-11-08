package main

import (
	"testing"

	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/normalize"
	"github.com/moke-cloud/SHIGOTOBA/threat-radar/collector/sources"
)

func TestBackfillFactsZDIOnly(t *testing.T) {
	in := []normalize.Item{
		{ID: "z", Title: "ZDI-26-833: Valkey clusterCreatePublishMsgBlock Heap-based Buffer Overflow Remote Code Execution Vulnerability"},
		{ID: "n", Title: "Hackers hit bank"},
	}
	out := backfillFacts(in)
	if out[0].Product != "Valkey clusterCreatePublishMsgBlock" || out[0].Impact != "rce" || out[1].Product != "" {
		t.Fatalf("out = %+v", out)
	}
	if in[0].Product != "" {
		t.Fatal("input mutated")
	}
}

func TestEPSSDisabledOnSkipFetch(t *testing.T) {
	cfg := &appConfig{}
	cfg.EPSS.Enabled = true
	if epssUnlessSkipped(cfg, sources.HTTPClientConfig{}, true) != nil {
		t.Fatal("skip-fetch must disable EPSS")
	}
	if epssUnlessSkipped(cfg, sources.HTTPClientConfig{}, false) == nil {
		t.Fatal("normal runs keep EPSS")
	}
}
