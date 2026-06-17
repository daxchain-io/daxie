package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/daxchain-io/daxie/internal/domain"
)

// receive_test.go pins the `daxie receive` thin-host boundary through the real
// Execute funnel (execCLI → newRootCmd → mapError): the flag mutual-exclusion +
// dependency rules that fail with USAGE exit 2 BEFORE the service opens (so no
// network/keystore is needed), plus the --nft / --contract+--token-id reference
// collapse. The blocking detection engine itself (the unbounded listen) is
// exercised in internal/service (fake-driven) and end-to-end against anvil in
// receive_integration_test.go — these unit cases never reach svc.Receive (which
// would block), they assert the cli rejects bad flag combos up front.

// --token and --nft are mutually exclusive → usage exit 2 (a receive listens for
// one asset).
func TestReceiveTokenAndNFTExclusive(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "receive", "--account", "treasury/0", "--token", "USDC", "--nft", "punks#1")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Errorf("stderr should explain the --token/--nft conflict: %q", stderr)
	}
}

// --exact without --amount is a usage error (there is no single transfer to
// match).
func TestReceiveExactNeedsAmount(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "receive", "--account", "treasury/0", "--exact")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "amount") {
		t.Errorf("stderr should mention the missing --amount: %q", stderr)
	}
}

// --new requires --wallet (the derive target).
func TestReceiveNewNeedsWallet(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "receive", "--new", "--amount", "0.1")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "wallet") {
		t.Errorf("stderr should mention the missing --wallet: %q", stderr)
	}
}

// --new derives a fresh address; passing --account too is a usage error.
func TestReceiveNewAndAccountConflict(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "receive", "--new", "--wallet", "treasury", "--account", "treasury/0", "--amount", "0.1")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// --nft together with --contract/--token-id is a usage error (pick one form).
func TestReceiveNFTAndContractConflict(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "receive", "--account", "a", "--nft", "punks#1", "--contract", "0xabc", "--token-id", "1")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// --contract without --token-id (and vice versa) is a usage error.
func TestReceiveContractNeedsTokenID(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "receive", "--account", "a", "--contract", "0xabc")
	if code != int(domain.ExitUsage) {
		t.Fatalf("--contract alone: exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	_, _, code = execCLI(t, "receive", "--account", "a", "--token-id", "1")
	if code != int(domain.ExitUsage) {
		t.Fatalf("--token-id alone: exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// A bad --timeout string is a usage error, surfaced by the cli parse before the
// service is consulted.
func TestReceiveBadTimeout(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "receive", "--account", "a", "--amount", "0.5", "--timeout", "not-a-duration")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE) for a bad --timeout", code, domain.ExitUsage)
	}
}

// An unknown flag on receive → exit 2 via the Cobra/pflag funnel.
func TestReceiveUnknownFlag(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "receive", "--account", "a", "--frobnicate")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// receive takes no positional args.
func TestReceiveNoArgs(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "receive", "0xdeadbeef")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE) for an unexpected positional", code, domain.ExitUsage)
	}
}

// `receive --help` lists every flag (the agent-discoverable surface) and exits 0.
func TestReceiveHelpListsFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "receive", "--help")
	if code != int(domain.ExitOK) {
		t.Fatalf("--help exit = %d, want 0", code)
	}
	for _, flag := range []string{"--account", "--new", "--wallet", "--name", "--amount",
		"--exact", "--token", "--nft", "--contract", "--token-id", "--confirmations",
		"--timeout", "--from-block", "--qr"} {
		if !strings.Contains(out, flag) {
			t.Errorf("receive --help missing %s\n%s", flag, out)
		}
	}
}

// combineNFTRef collapses the --nft / --contract+--token-id forms exactly: --nft
// passes through; --contract+--token-id becomes <contract>#<id>; neither yields
// "" (the ETH/token path); a partial form is rejected; both forms together is
// rejected.
func TestCombineNFTRef(t *testing.T) {
	t.Run("nft passthrough", func(t *testing.T) {
		got, err := combineNFTRef("punks#42", "", "")
		if err != nil || got != "punks#42" {
			t.Fatalf("got (%q, %v), want (punks#42, nil)", got, err)
		}
	})
	t.Run("contract+token-id collapse", func(t *testing.T) {
		got, err := combineNFTRef("", "0xabc", "42")
		if err != nil || got != "0xabc#42" {
			t.Fatalf("got (%q, %v), want (0xabc#42, nil)", got, err)
		}
	})
	t.Run("neither is empty (eth/token path)", func(t *testing.T) {
		got, err := combineNFTRef("", "", "")
		if err != nil || got != "" {
			t.Fatalf("got (%q, %v), want (\"\", nil)", got, err)
		}
	})
	t.Run("contract without token-id rejected", func(t *testing.T) {
		if _, err := combineNFTRef("", "0xabc", ""); err == nil {
			t.Fatal("expected an error for --contract without --token-id")
		}
	})
	t.Run("token-id without contract rejected", func(t *testing.T) {
		if _, err := combineNFTRef("", "", "42"); err == nil {
			t.Fatal("expected an error for --token-id without --contract")
		}
	})
	t.Run("both forms rejected", func(t *testing.T) {
		if _, err := combineNFTRef("punks#42", "0xabc", "42"); err == nil {
			t.Fatal("expected an error for --nft AND --contract/--token-id")
		}
	})
}

// renderReceiveOutcome translates the service's terminal outcome into the §5.7
// exit projection: complete (Exit 0) → nil; timeout (Exit 8) → a typed
// receive.timeout error so mapError projects exit 8; a true error funnels
// straight through.
func TestRenderReceiveOutcome(t *testing.T) {
	t.Run("complete returns nil", func(t *testing.T) {
		if err := renderReceiveOutcome(domain.ReceiveResult{Status: "complete", Exit: 0}, nil); err != nil {
			t.Fatalf("complete must return nil, got %v", err)
		}
	})
	t.Run("timeout returns a code-8 domain error", func(t *testing.T) {
		err := renderReceiveOutcome(domain.ReceiveResult{Status: "timeout", Exit: int(domain.ExitTimeoutPending)}, nil)
		if err == nil {
			t.Fatal("timeout must return a non-nil error carrying exit 8")
		}
		var de *domain.Error
		if !asDomainError(err, &de) {
			t.Fatalf("timeout error must be a *domain.Error, got %T", err)
		}
		if de.Exit != domain.ExitTimeoutPending {
			t.Errorf("timeout error exit = %d, want %d", de.Exit, domain.ExitTimeoutPending)
		}
	})
	t.Run("true error passes through (keystore.read_only ⇒ exit 10)", func(t *testing.T) {
		// The --new writable-keystore rule: a keystore.read_only error funnels through
		// unchanged so the §5.7 registry projects exit 10 (ExitNotFound family).
		want := domain.New(domain.CodeKeystoreReadOnly, "read only")
		if want.Exit != domain.ExitNotFound {
			t.Fatalf("keystore.read_only must map to exit 10 (ExitNotFound), got %d", want.Exit)
		}
		if got := renderReceiveOutcome(domain.ReceiveResult{}, want); got != want {
			t.Fatalf("a true error must pass through unchanged, got %v", got)
		}
	})
}

// buildServiceOptions MUST inject a real ctx-aware Sleep (and Clock) into
// service.Options (issue #3): without Sleep, service.Open falls back to noDelaySleep
// and a real `daxie receive` busy-spins, pegging CPU and hammering the RPC instead
// of honoring receive.poll-interval. This asserts the frontend wires it (Sleep
// non-nil) so the production cadence can never silently regress to a spin.
func TestBuildServiceOptionsInjectsRealSleeper(t *testing.T) {
	isolateEnv(t)
	rs := &rootState{}
	opts := buildServiceOptions(rs)
	if opts.Sleep == nil {
		t.Fatal("buildServiceOptions did not inject Options.Sleep; the receive poll loop will busy-spin (no poll-interval cadence)")
	}
	if opts.Clock == nil {
		t.Fatal("buildServiceOptions did not inject Options.Clock")
	}
	// The injected sleeper is the real one — it honors ctx cancellation (does not
	// busy-return on every call) and respects the duration.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := opts.Sleep(ctx, time.Hour); err == nil {
		t.Fatal("the injected Sleep must be ctx-aware (return on cancellation), not a no-delay stub")
	}
}

// realSleeper is ctx-aware: a non-trivial duration returns ctx.Err() the moment the
// context is cancelled (a SIGTERM during a listen) rather than sleeping the full
// duration — the property the receive loop relies on to surface a resumable timeout.
func TestRealSleeperHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	if err := realSleeper(ctx, time.Hour); err == nil {
		t.Fatal("realSleeper must return ctx.Err() immediately when the context is cancelled, not sleep an hour")
	}
	// A zero/negative duration is an immediate non-blocking yield.
	if err := realSleeper(context.Background(), 0); err != nil {
		t.Fatalf("realSleeper(0) = %v, want nil (immediate yield)", err)
	}
	// A short positive duration actually elapses and returns nil.
	if err := realSleeper(context.Background(), time.Millisecond); err != nil {
		t.Fatalf("realSleeper(1ms) = %v, want nil", err)
	}
}

// asDomainError is a tiny errors.As helper kept local so the test reads clearly.
func asDomainError(err error, target **domain.Error) bool {
	de, ok := err.(*domain.Error)
	if ok {
		*target = de
	}
	return ok
}
