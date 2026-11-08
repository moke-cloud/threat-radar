package sources

import (
	"reflect"
	"testing"
)

func TestParseCVSSVector(t *testing.T) {
	cases := map[string]*Attack{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H":                    {AV: "N", PR: "N", UI: "N"},
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H":                    {AV: "L", PR: "L", UI: "R"},
		"CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N": {AV: "A", PR: "H", UI: "R"},
		"AV:N/AC:L/Au:N/C:P/I:P/A:P":                                      {AV: "N", PR: "N"},
		"AV:N/AC:L/Au:S/C:P/I:P/A:P":                                      {AV: "N", PR: "L"},
	}
	for in, want := range cases {
		if got := ParseCVSSVector(in); !reflect.DeepEqual(got, want) {
			t.Errorf("%s -> %+v, want %+v", in, got, want)
		}
	}
	if ParseCVSSVector("") != nil || ParseCVSSVector("garbage") != nil {
		t.Error("invalid vectors must give nil")
	}
	if ParseCVSSVector("CVSS:3.1/AV:X/PR:N") != nil {
		t.Error("unknown AV value must give nil")
	}
}

func TestZDIFacts(t *testing.T) {
	f := ZDIFacts(
		"ZDI-26-897: (Pwn2Own) Home Assistant Green aiohttp_client Server-Side Request Forgery Vulnerability",
		"This vulnerability allows network-adjacent attackers to initiate arbitrary server-side requests on affected installations of Home Assistant Green. Authentication is not required to exploit this vulnerability.")
	if f.Product != "Home Assistant Green aiohttp_client" || f.Impact != "ssrf" {
		t.Fatalf("facts = %+v", f)
	}
	if !reflect.DeepEqual(f.Attack, &Attack{AV: "A", PR: "N", UI: "N"}) {
		t.Fatalf("attack = %+v", f.Attack)
	}

	f = ZDIFacts(
		"ZDI-26-833: Valkey clusterCreatePublishMsgBlock Heap-based Buffer Overflow Remote Code Execution Vulnerability",
		"This vulnerability allows remote attackers to execute arbitrary code on affected installations of Valkey. Authentication is required to exploit this vulnerability. User interaction is required to exploit this vulnerability in that the target must open a file.")
	if f.Product != "Valkey clusterCreatePublishMsgBlock" || f.Impact != "rce" ||
		!reflect.DeepEqual(f.CWEs, []string{"CWE-122"}) {
		t.Fatalf("facts = %+v", f)
	}
	if !reflect.DeepEqual(f.Attack, &Attack{AV: "N", PR: "L", UI: "R"}) {
		t.Fatalf("attack = %+v", f.Attack)
	}

	f = ZDIFacts("ZDI-26-830: (0Day) Apple Safari jsToWasm IC Entrypoint Type Confusion Remote Code Execution Vulnerability", "")
	if f.Product != "Apple Safari jsToWasm IC Entrypoint" || !reflect.DeepEqual(f.CWEs, []string{"CWE-843"}) || f.Attack != nil {
		t.Fatalf("facts = %+v", f)
	}

	f = ZDIFacts("ZDI-26-1: (0Day) (Pwn2Own) Alpine iLX-F511 SSH Hard-Coded Credentials Remote Code Execution Vulnerability",
		"This vulnerability allows remote attackers to execute arbitrary code on affected installations of LibreOffice. User interaction is required to exploit this vulnerability.")
	if f.Product != "Alpine iLX-F511 SSH" || !reflect.DeepEqual(f.CWEs, []string{"CWE-798"}) ||
		!reflect.DeepEqual(f.Attack, &Attack{AV: "N", UI: "R"}) {
		t.Fatalf("facts = %+v attack %+v", f, f.Attack)
	}

	if f := ZDIFacts("Not a ZDI title", "x"); f.Product != "" || f.Impact != "" {
		t.Fatalf("non-ZDI title parsed: %+v", f)
	}
}

func TestKEVProduct(t *testing.T) {
	if got := kevProduct("Microsoft", "Windows"); got != "Microsoft Windows" {
		t.Fatal(got)
	}
	if got := kevProduct("WordPress", "WordPress Core"); got != "WordPress Core" {
		t.Fatal(got)
	}
	if got := kevProduct("", "Foo"); got != "Foo" {
		t.Fatal(got)
	}
}

func TestPickCWEs(t *testing.T) {
	w := []nvdWeakness{
		{Description: []nvdDesc{{Lang: "en", Value: "CWE-787"}, {Lang: "en", Value: "NVD-CWE-noinfo"}}},
		{Description: []nvdDesc{{Lang: "en", Value: "CWE-787"}, {Lang: "en", Value: "CWE-121"}}},
	}
	if got := pickCWEs(w); !reflect.DeepEqual(got, []string{"CWE-787", "CWE-121"}) {
		t.Fatalf("got %v", got)
	}
}
