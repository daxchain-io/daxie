package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// ceremony_test.go covers the §3.5 display-once + recorded-it proof. The
// interactive os.Stdin path is exercised through verifyRecordedProof (which takes
// an io.Reader), and the --yes / no-TTY decision branches through
// mnemonicCeremony.

const ceremonyMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

// TestMnemonicCeremonyYesEchoes asserts the --yes path defers a single echo to the
// result renderer and never touches the TTY.
func TestMnemonicCeremonyYesEchoes(t *testing.T) {
	var errw bytes.Buffer
	disp, err := mnemonicCeremony(&errw, true, ceremonyMnemonic, "")
	if err != nil {
		t.Fatalf("ceremony(--yes): %v", err)
	}
	if !disp.echoInResult {
		t.Error("--yes must echo the mnemonic once in the result")
	}
	if errw.Len() != 0 {
		t.Errorf("--yes must not write the mnemonic to stderr: %q", errw.String())
	}
}

// TestMnemonicCeremonyNoTTYNoYesRefuses asserts the fail-closed branch: no TTY and
// no --yes refuses with usage.confirmation_required (exit 2) and never prints the
// mnemonic. (In the test process stdin is not a terminal, so stdinIsTTY()==false.)
func TestMnemonicCeremonyNoTTYNoYesRefuses(t *testing.T) {
	var errw bytes.Buffer
	_, err := mnemonicCeremony(&errw, false, ceremonyMnemonic, "")
	if err == nil {
		t.Fatal("no TTY + no --yes must refuse to display a new mnemonic")
	}
	var de *domain.Error
	if !asDomainErr(err, &de) || de.Code != "usage.confirmation_required" {
		t.Fatalf("error = %v, want usage.confirmation_required", err)
	}
	if strings.Contains(errw.String(), "abandon") {
		t.Errorf("refused path leaked the mnemonic: %q", errw.String())
	}
}

// TestVerifyRecordedProofMatch asserts a correct re-entry of the two requested
// positions passes (deterministic positions 0 and 11 of the abandon… vector).
func TestVerifyRecordedProofMatch(t *testing.T) {
	words := strings.Fields(ceremonyMnemonic)
	a, b := 0, 11 // "abandon" and "about"
	var errw bytes.Buffer
	in := strings.NewReader(words[a] + "\n" + words[b] + "\n")
	if err := verifyRecordedProof(&errw, in, words, a, b); err != nil {
		t.Fatalf("correct re-entry should pass: %v", err)
	}
	if !strings.Contains(errw.String(), "Confirmed") {
		t.Errorf("expected a confirmation line, got: %q", errw.String())
	}
	// Both requested positions must have been prompted (1-based labels).
	if !strings.Contains(errw.String(), "word #1") || !strings.Contains(errw.String(), "word #12") {
		t.Errorf("proof did not prompt both positions: %q", errw.String())
	}
}

// TestVerifyRecordedProofMismatch asserts a wrong re-entry aborts with
// usage.confirmation_required.
func TestVerifyRecordedProofMismatch(t *testing.T) {
	words := strings.Fields(ceremonyMnemonic)
	var errw bytes.Buffer
	// First answer correct, second wrong → must abort on the second.
	in := strings.NewReader(words[0] + "\nwrong\n")
	err := verifyRecordedProof(&errw, in, words, 0, 5)
	if err == nil {
		t.Fatal("a wrong re-entry must abort the proof")
	}
	var de *domain.Error
	if !asDomainErr(err, &de) || de.Code != "usage.confirmation_required" {
		t.Fatalf("error = %v, want usage.confirmation_required", err)
	}
}

// TestTwoDistinctPositions asserts the picker returns two distinct in-range
// positions with a < b, across many draws.
func TestTwoDistinctPositions(t *testing.T) {
	for i := 0; i < 500; i++ {
		a, b, err := twoDistinctPositions(12)
		if err != nil {
			t.Fatalf("pick: %v", err)
		}
		if a < 0 || b >= 12 || a >= b {
			t.Fatalf("positions out of order/range: a=%d b=%d", a, b)
		}
	}
}

// asDomainErr is a tiny errors.As wrapper local to the cli tests.
func asDomainErr(err error, target **domain.Error) bool {
	for err != nil {
		if e, ok := err.(*domain.Error); ok {
			*target = e
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
