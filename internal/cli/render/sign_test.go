package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// sign_test.go pins the human renderers for the M9 sign/verify views: the essential
// value prints even under --quiet; signer/digest/scheme context lines are
// quiet-suppressed.

func TestSigResultEssential(t *testing.T) {
	r := domain.SigResult{
		Signature: "0xaabbccdd",
		Signer:    "0x1111111111111111111111111111111111111111",
		Digest:    "0xdeadbeef",
		Scheme:    "eip191",
	}

	// --quiet still prints the signature (the one essential output).
	var quiet bytes.Buffer
	SigResultHuman(&quiet, Mode{Quiet: true}, r)
	if !strings.HasPrefix(quiet.String(), r.Signature+"\n") {
		t.Errorf("quiet SigResultHuman must print the signature; got %q", quiet.String())
	}
	if strings.Contains(quiet.String(), "signer:") {
		t.Errorf("quiet SigResultHuman must suppress context; got %q", quiet.String())
	}

	// full mode carries the context lines.
	var full bytes.Buffer
	SigResultHuman(&full, Mode{}, r)
	out := full.String()
	for _, want := range []string{r.Signer, r.Digest, "eip191"} {
		if !strings.Contains(out, want) {
			t.Errorf("SigResultHuman missing %q:\n%s", want, out)
		}
	}
}

func TestVerifyResultValid(t *testing.T) {
	r := domain.VerifyResult{
		Valid:     true,
		Signer:    "0x1111111111111111111111111111111111111111",
		Recovered: "0x1111111111111111111111111111111111111111",
		Digest:    "0xdeadbeef",
		Scheme:    "eip712",
	}
	var quiet bytes.Buffer
	VerifyResultHuman(&quiet, Mode{Quiet: true}, r)
	if !strings.HasPrefix(quiet.String(), "valid\n") {
		t.Errorf("a valid verify must render 'valid' as the headline; got %q", quiet.String())
	}
}

func TestVerifyResultInvalid(t *testing.T) {
	r := domain.VerifyResult{
		Valid:     false,
		Signer:    "0x1111111111111111111111111111111111111111",
		Recovered: "0x2222222222222222222222222222222222222222",
		Digest:    "0xdeadbeef",
		Scheme:    "eip191",
	}
	var full bytes.Buffer
	VerifyResultHuman(&full, Mode{}, r)
	out := full.String()
	if !strings.HasPrefix(out, "invalid\n") {
		t.Errorf("an invalid verify must render 'invalid' as the headline; got %q", out)
	}
	// The recovered address is surfaced so an agent can see WHO actually signed.
	if !strings.Contains(out, r.Recovered) {
		t.Errorf("VerifyResultHuman must surface the recovered address:\n%s", out)
	}
}
