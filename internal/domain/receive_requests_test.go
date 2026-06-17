package domain

import "testing"

func TestResolveReceiveMode(t *testing.T) {
	cases := []struct {
		name    string
		req     ReceiveRequest
		want    ReceiveMode
		wantErr string // "" ⇒ no error; else a substring of the error code
	}{
		{
			name: "no amount no asset ⇒ any",
			req:  ReceiveRequest{},
			want: ModeAny,
		},
		{
			name: "amount only ⇒ cumulative",
			req:  ReceiveRequest{Amount: "0.5"},
			want: ModeCumulative,
		},
		{
			name: "amount + exact ⇒ exact",
			req:  ReceiveRequest{Amount: "0.5", Exact: true},
			want: ModeExact,
		},
		{
			name: "nft ⇒ nft",
			req:  ReceiveRequest{NFT: "punks#42"},
			want: ModeNFT,
		},
		{
			name: "nft + amount (1155 quantity) ⇒ nft",
			req:  ReceiveRequest{NFT: "0xabc#7", Amount: "5"},
			want: ModeNFT,
		},
		{
			name: "token + amount ⇒ cumulative",
			req:  ReceiveRequest{Token: "USDC", Amount: "100"},
			want: ModeCumulative,
		},
		{
			name: "bare token (no amount) ⇒ any",
			req:  ReceiveRequest{Token: "USDC"},
			want: ModeAny,
		},
		{
			name:    "exact without amount ⇒ usage error",
			req:     ReceiveRequest{Exact: true},
			wantErr: "usage.exact_needs_amount",
		},
		{
			name:    "token + nft together ⇒ usage error",
			req:     ReceiveRequest{Token: "USDC", NFT: "punks#1"},
			wantErr: "usage.asset_conflict",
		},
		{
			name:    "new without wallet ⇒ usage error",
			req:     ReceiveRequest{New: true},
			wantErr: "usage.new_needs_wallet",
		},
		{
			name: "new with wallet ⇒ ok (any)",
			req:  ReceiveRequest{New: true, Wallet: "treasury"},
			want: ModeAny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveReceiveMode(tc.req)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ResolveReceiveMode(%+v) = %q, nil; want error %q", tc.req, got, tc.wantErr)
				}
				if AsError(err).Code != tc.wantErr {
					t.Fatalf("error code = %q, want %q", AsError(err).Code, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveReceiveMode(%+v) unexpected error: %v", tc.req, err)
			}
			if got != tc.want {
				t.Fatalf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsAttributable(t *testing.T) {
	if !IsAttributable(AttribTx) {
		t.Error("tx must be attributable (satisfies --exact)")
	}
	if !IsAttributable(AttribLog) {
		t.Error("log must be attributable (satisfies --exact)")
	}
	if IsAttributable(AttribBalanceDelta) {
		t.Error("balance-delta must NOT be attributable (cannot satisfy --exact) — the §5.8 non-negotiable")
	}
}

func TestReceiveTargetTimeoutNullable(t *testing.T) {
	// An unbounded wait is Timeout=nil; the §5.8 listening line emits "timeout":null.
	tgt := ReceiveTarget{Mode: ModeCumulative, Amount: "100", Confirmations: 2, Timeout: nil}
	if tgt.Timeout != nil {
		t.Fatalf("unbounded target must carry a nil Timeout (renders as null)")
	}
	// A bounded wait carries the duration string.
	s := "3s"
	tgt2 := ReceiveTarget{Mode: ModeCumulative, Timeout: &s}
	if tgt2.Timeout == nil || *tgt2.Timeout != "3s" {
		t.Fatalf("bounded target must carry the duration string")
	}
}
