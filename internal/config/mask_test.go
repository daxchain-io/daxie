package config

import "testing"

// TestMaskSecretRefsKeepsReferences: a ${env:}/${file:} reference is the reference,
// not the secret — it is shown verbatim so the operator sees which var/file is used.
func TestMaskSecretRefsKeepsReferences(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}",
			"https://eth-mainnet.g.alchemy.com/v2/${env:ALCHEMY_API_KEY}",
		},
		{
			"Bearer ${file:~/.config/daxie/secrets/jwt}",
			"Bearer ${file:~/.config/daxie/secrets/jwt}",
		},
		{
			"https://eth.llamarpc.com",
			"https://eth.llamarpc.com",
		},
		{
			"$${not-a-ref}", // escape preserved
			"$${not-a-ref}",
		},
	}
	for _, c := range cases {
		if got := MaskSecretRefs(c.in); got != c.want {
			t.Errorf("MaskSecretRefs(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMaskSecretRefsHidesLiteral: a literal opaque API key embedded directly in the
// URL (no reference) is reduced to *** so it is not echoed back by `rpc show`.
func TestMaskSecretRefsHidesLiteral(t *testing.T) {
	in := "https://eth-mainnet.g.alchemy.com/v2/abcd1234EFGH5678ijkl9012mnop"
	got := MaskSecretRefs(in)
	if got == in {
		t.Fatalf("literal key was not masked: %q", got)
	}
	// the host must survive; only the opaque segment is replaced.
	if want := "https://eth-mainnet.g.alchemy.com/v2/***"; got != want {
		t.Errorf("MaskSecretRefs literal = %q, want %q", got, want)
	}
}

// TestMaskKeepsShortPathWords: ordinary short path words and the host are not
// masked (no false positives).
func TestMaskKeepsShortPathWords(t *testing.T) {
	in := "https://mainnet.infura.io/v3/networks/eth"
	if got := MaskSecretRefs(in); got != in {
		t.Errorf("short path words masked unexpectedly: %q", got)
	}
}

// TestDetectLiteralSecret: URL with a literal key flags; reference does not; auth
// header with a literal token flags; header with a reference does not.
func TestDetectLiteralSecret(t *testing.T) {
	// literal in URL
	if hits := detectLiteralSecret("https://x.com/v2/abcd1234EFGH5678ijkl9012mnop", nil); len(hits) == 0 {
		t.Error("expected URL literal-secret hit")
	}
	// reference in URL → no hit
	if hits := detectLiteralSecret("https://x.com/v2/${env:KEY}", nil); len(hits) != 0 {
		t.Errorf("reference URL should not be flagged: %v", hits)
	}
	// auth header literal token
	if hits := detectLiteralSecret("https://x.com", map[string]string{"Authorization": "Bearer abcdEFGH1234ijkl"}); len(hits) == 0 {
		t.Error("expected header literal-secret hit")
	}
	// auth header reference → no hit
	if hits := detectLiteralSecret("https://x.com", map[string]string{"Authorization": "Bearer ${file:~/jwt}"}); len(hits) != 0 {
		t.Errorf("reference header should not be flagged: %v", hits)
	}
	// non-auth header is not flagged (too noisy)
	if hits := detectLiteralSecret("https://x.com", map[string]string{"X-Trace-Id": "abcdEFGH1234ijklmnop"}); len(hits) != 0 {
		t.Errorf("non-auth header should not be flagged: %v", hits)
	}
}
