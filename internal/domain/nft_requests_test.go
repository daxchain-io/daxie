package domain

import "testing"

// nft_requests_test.go pins the ParseNFTRef syntactic split: the
// <collection>#<tokenId> form vs a bare individual-NFT alias, the error cases, and
// the load-bearing property that the token id stays a STRING (never parsed to int).

func TestParseNFTRef_CollectionHashID(t *testing.T) {
	r, err := ParseNFTRef("punks#42")
	if err != nil {
		t.Fatalf("ParseNFTRef: %v", err)
	}
	if r.Collection != "punks" || r.TokenID != "42" || r.Alias != "" {
		t.Fatalf("got %+v, want {Collection:punks TokenID:42 Alias:}", r)
	}
	if r.IsAlias() {
		t.Error("a <collection>#<id> ref must not report IsAlias()")
	}
}

func TestParseNFTRef_RawAddressCollection(t *testing.T) {
	r, err := ParseNFTRef("0x00000000000000000000000000000000000000aa#7")
	if err != nil {
		t.Fatalf("ParseNFTRef raw: %v", err)
	}
	if r.Collection != "0x00000000000000000000000000000000000000aa" || r.TokenID != "7" {
		t.Fatalf("got %+v, want the raw 0x collection + token id 7", r)
	}
}

func TestParseNFTRef_BareAlias(t *testing.T) {
	r, err := ParseNFTRef("my-punk")
	if err != nil {
		t.Fatalf("ParseNFTRef alias: %v", err)
	}
	if !r.IsAlias() || r.Alias != "my-punk" || r.Collection != "" || r.TokenID != "" {
		t.Fatalf("got %+v, want a bare alias my-punk", r)
	}
}

func TestParseNFTRef_BigTokenIDStaysString(t *testing.T) {
	// A 2^200 token id must survive as a decimal STRING (never an int64/float).
	big := "1606938044258990275541962092341162602522202993782792835301376" // 2^200
	r, err := ParseNFTRef("punks#" + big)
	if err != nil {
		t.Fatalf("ParseNFTRef big id: %v", err)
	}
	if r.TokenID != big {
		t.Fatalf("token id = %q, want %q (magnitude-safe string)", r.TokenID, big)
	}
}

func TestParseNFTRef_Errors(t *testing.T) {
	cases := []struct {
		name, in string
	}{
		{"empty", ""},
		{"whitespace", "   "},
		{"empty-collection", "#42"},
		{"empty-id", "punks#"},
		{"double-hash", "punks#4#2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseNFTRef(tc.in)
			if err == nil {
				t.Fatalf("ParseNFTRef(%q) should error", tc.in)
			}
			de := AsError(err)
			if de.Exit != ExitUsage {
				t.Errorf("exit = %d, want 2 (usage) for %q", de.Exit, tc.in)
			}
			if de.Code != CodeUsage+".bad_nft_ref" {
				t.Errorf("code = %q, want usage.bad_nft_ref for %q", de.Code, tc.in)
			}
		})
	}
}

func TestParseNFTRef_TrimsWhitespace(t *testing.T) {
	r, err := ParseNFTRef("  punks # 42 ")
	if err != nil {
		t.Fatalf("ParseNFTRef trimmed: %v", err)
	}
	if r.Collection != "punks" || r.TokenID != "42" {
		t.Fatalf("got %+v, want trimmed {punks,42}", r)
	}
}
