package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/cli/render"
	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
)

// tx_test.go exercises the `daxie tx` command surface through the real Execute
// funnel (execCLI → newRootCmd → mapError): flag→request mapping validation, the
// §5.7 exit-code mapping for usage errors, and the command structure. The
// signing-side behavior (the §2.7 kernel, the §5.1 pipeline, gas, journal, policy)
// is unit-tested in internal/service and exercised end-to-end against anvil in
// tx_integration_test.go — these cli tests pin the thin-host boundary: that flags
// map to the request and that the central error funnel projects the right code.

// `tx send` with no --to is a usage error (exit 2) — caught before the service
// opens, so it needs no network/keystore.
func TestTxSendMissingTo(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "tx", "send", "--amount", "0.5")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "to") {
		t.Errorf("stderr should mention the missing --to: %q", stderr)
	}
}

// `tx send` with no --amount is a usage error (exit 2).
func TestTxSendMissingAmount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "tx", "send", "--to", "0x52908400098527886E0F7030069857D2E4169EE7")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// A bad --timeout string is a usage error (exit 2), surfaced by the cli parse
// before the service is consulted.
func TestTxSendBadTimeout(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "tx", "send",
		"--to", "0x52908400098527886E0F7030069857D2E4169EE7",
		"--amount", "0.5", "--wait", "--timeout", "not-a-duration", "--yes")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE) for a bad --timeout", code, domain.ExitUsage)
	}
}

// Unknown subcommand under tx → exit 2 (USAGE).
func TestTxUnknownSubcommand(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "tx", "frobnicate")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// Unknown flag on tx send → exit 2 (USAGE), via the Cobra/pflag funnel.
func TestTxSendUnknownFlag(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "tx", "send",
		"--to", "0x52908400098527886E0F7030069857D2E4169EE7",
		"--amount", "0.5", "--frobnicate")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// `tx status` requires exactly one hash arg.
func TestTxStatusArgCount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "tx", "status")
	if code != int(domain.ExitUsage) {
		t.Fatalf("no-arg status: exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	_, _, code = execCLI(t, "tx", "status", "0xa", "0xb")
	if code != int(domain.ExitUsage) {
		t.Fatalf("two-arg status: exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// `tx wait` / `tx speedup` / `tx cancel` each require exactly one hash arg.
func TestTxHashCommandsArgCount(t *testing.T) {
	isolateEnv(t)
	for _, sub := range []string{"wait", "speedup", "cancel"} {
		_, _, code := execCLI(t, "tx", sub)
		if code != int(domain.ExitUsage) {
			t.Errorf("tx %s with no hash: exit = %d, want %d (USAGE)", sub, code, domain.ExitUsage)
		}
	}
}

// The tx command tree exposes the documented subcommands in --help (the surface
// contract). A missing subcommand here means the tree was wired wrong.
func TestTxHelpListsSubcommands(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "tx", "--help")
	if code != int(domain.ExitOK) {
		t.Fatalf("tx --help exit = %d, want 0", code)
	}
	for _, sub := range []string{"send", "status", "wait", "list", "speedup", "cancel"} {
		if !strings.Contains(out, sub) {
			t.Errorf("tx --help missing subcommand %q:\n%s", sub, out)
		}
	}
}

// renderTxOutcome is the §5.3/§5.9 contract: a TIMEOUT outcome (a populated
// TxResult carrying a hash + Resume, paired with a tx.wait_timeout error) must
// still emit exactly ONE final JSON object on STDOUT, then return the error so the
// central funnel exits 8. The naive `if err != nil { return err }` would swallow
// the stdout object — this test is the regression guard for that.
func TestRenderTxOutcomeTimeoutEmitsStdoutThenError(t *testing.T) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)

	res := domain.TxResult{
		Hash:   "0xpending",
		Status: domain.TxStatusTimeout,
		Resume: "daxie tx wait 0xpending",
	}
	timeoutErr := domain.New(domain.CodeTxWaitTimeout, "wait deadline reached; still pending")

	err := renderTxOutcome(cmd, render.Mode{JSON: true}, res, timeoutErr)
	if err == nil {
		t.Fatal("renderTxOutcome must return the timeout error for the exit code")
	}
	var de *domain.Error
	if !errors.As(err, &de) || de.Code != domain.CodeTxWaitTimeout {
		t.Fatalf("returned error = %v, want %s", err, domain.CodeTxWaitTimeout)
	}
	// stdout carries exactly one JSON object with the timeout status + resume hint.
	var got domain.TxResult
	dec := json.NewDecoder(strings.NewReader(stdout.String()))
	if derr := dec.Decode(&got); derr != nil {
		t.Fatalf("stdout object not valid JSON: %v (%q)", derr, stdout.String())
	}
	if dec.More() {
		t.Errorf("expected exactly one stdout object, found more: %q", stdout.String())
	}
	if got.Status != domain.TxStatusTimeout || got.Resume == "" {
		t.Errorf("stdout result = %+v, want timeout status + resume", got)
	}
}

// A bare pre-broadcast error (empty result: bad flag, policy denial, dial failure)
// writes NOTHING to stdout and funnels straight to the error envelope — stdout must
// stay clean so the single-object contract is never polluted on a hard failure.
func TestRenderTxOutcomeBareErrorNoStdout(t *testing.T) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)

	err := renderTxOutcome(cmd, render.Mode{JSON: true}, domain.TxResult{}, domain.New(domain.CodeUsage+".bad", "boom"))
	if err == nil {
		t.Fatal("renderTxOutcome must return the bare error")
	}
	if stdout.Len() != 0 {
		t.Errorf("a bare pre-broadcast error must not write stdout; got %q", stdout.String())
	}
}

// A success outcome (populated result, nil error) emits the object and returns nil.
func TestRenderTxOutcomeSuccess(t *testing.T) {
	var stdout bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&stdout)

	res := domain.TxResult{Hash: "0xok", Status: domain.TxStatusConfirmed}
	if err := renderTxOutcome(cmd, render.Mode{JSON: true}, res, nil); err != nil {
		t.Fatalf("success outcome returned error: %v", err)
	}
	if !strings.Contains(stdout.String(), "0xok") {
		t.Errorf("success stdout missing hash: %q", stdout.String())
	}
}

// `tx send --help` documents the gas + wait + dry-run flags (the agent-facing
// surface). This pins that the flag groups are bound.
func TestTxSendHelpFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "tx", "send", "--help")
	if code != 0 {
		t.Fatalf("tx send --help exit = %d, want 0", code)
	}
	for _, fl := range []string{"--from", "--to", "--amount", "--gas-limit", "--max-fee", "--priority-fee", "--speed", "--legacy", "--nonce", "--dry-run", "--wait", "--confirmations", "--timeout", "--token"} {
		if !strings.Contains(out, fl) {
			t.Errorf("tx send --help missing flag %q:\n%s", fl, out)
		}
	}
}
