package cli

import (
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// nft_test.go drives the `daxie nft` command tree through the real Execute funnel
// (execCLI → newRootCmd → mapError): the flag→request wiring + the §5.7 exit codes
// on the paths that fail BEFORE any dial (missing flags, arg counts, bad refs). The
// chain-touching happy paths (add/send/show/list against deployed NFTs) are covered
// by the integration tests against anvil.

func TestNFTHelpListsSubcommands(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "nft", "--help")
	if code != 0 {
		t.Fatalf("nft --help exit = %d, want 0", code)
	}
	for _, sub := range []string{"add", "alias", "aliases", "list", "show", "send"} {
		if !strings.Contains(out, sub) {
			t.Errorf("nft --help missing subcommand %q:\n%s", sub, out)
		}
	}
}

func TestNFTAddArgCount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "nft", "add")
	if code != int(domain.ExitUsage) {
		t.Fatalf("nft add (no arg) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestNFTAliasArgCount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "nft", "alias", "only-one-arg")
	if code != int(domain.ExitUsage) {
		t.Fatalf("nft alias (1 arg) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// send REQUIRES --to — caught before any dial.
func TestNFTSendMissingTo(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "nft", "send", "--nft", "punks#1", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("send without --to exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "to") {
		t.Errorf("error should mention the missing --to:\n%s", stderr)
	}
}

// send REQUIRES --nft — caught before any dial.
func TestNFTSendMissingNFT(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "nft", "send", "--to", "0x000000000000000000000000000000000000bEEF", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("send without --nft exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "nft") {
		t.Errorf("error should mention the missing --nft:\n%s", stderr)
	}
}

// send binds the shared wait flags + --amount (so the broadcasting outcomes flow
// through the same machine as tx send): assert the flags exist on the surface.
func TestNFTSendBindsFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "nft", "send", "--help")
	if code != 0 {
		t.Fatalf("nft send --help exit = %d, want 0", code)
	}
	for _, fl := range []string{"--to", "--nft", "--amount", "--from", "--dry-run", "--wait", "--confirmations", "--timeout"} {
		if !strings.Contains(out, fl) {
			t.Errorf("nft send --help missing flag %q:\n%s", fl, out)
		}
	}
}

// show with neither a positional ref nor --contract is a usage error (bad_nft_ref),
// caught before any dial.
func TestNFTShowMissingRef(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "nft", "show")
	if code != int(domain.ExitUsage) {
		t.Fatalf("show with no ref exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// show with BOTH a positional ref and --contract is mutually exclusive (usage).
func TestNFTShowRefAndContractMutuallyExclusive(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "nft", "show", "punks#1", "--contract", "0x000000000000000000000000000000000000bEEF", "--token-id", "1")
	if code != int(domain.ExitUsage) {
		t.Fatalf("show ref + --contract exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// show takes at most one positional arg.
func TestNFTShowArgCount(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "nft", "show", "punks#1", "extra-arg")
	if code != int(domain.ExitUsage) {
		t.Fatalf("show (2 args) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}
