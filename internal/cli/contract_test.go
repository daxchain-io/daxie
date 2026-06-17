package cli

import (
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// contract_test.go drives the `daxie contract` + `policy contract` command trees
// through the real Execute funnel (execCLI → newRootCmd → mapError): the flag→request
// wiring, the ABI-source precedence rejections, the arg counts, and the §5.7 exit codes
// on the paths that fail BEFORE any dial (missing ABI source, ambiguous source, bad
// calldata, a non-indexed log filter, missing --selector). The chain-touching happy
// paths + the classify-into-KindApprove crux are covered by the integration tests
// against anvil (contract_integration_test.go).

func TestContractHelpListsSubcommands(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "contract", "--help")
	if code != 0 {
		t.Fatalf("contract --help exit = %d, want 0", code)
	}
	for _, sub := range []string{"add", "list", "show", "remove", "call", "send", "logs", "encode", "decode"} {
		if !strings.Contains(out, sub) {
			t.Errorf("contract --help missing subcommand %q:\n%s", sub, out)
		}
	}
}

func TestContractSendHelpListsFlags(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "contract", "send", "--help")
	if code != 0 {
		t.Fatalf("contract send --help exit = %d, want 0", code)
	}
	// The send surface is IDENTICAL to tx send's gas+wait + the ABI source + --value,
	// PLUS the deliberate --unlimited acknowledgement (the typed-path-parity ceremony).
	for _, flag := range []string{"--value", "--from", "--abi", "--abi-stdin", "--sig", "--gas-limit", "--max-fee", "--priority-fee", "--gas-price", "--speed", "--legacy", "--nonce", "--dry-run", "--unlimited", "--wait", "--confirmations", "--timeout"} {
		if !strings.Contains(out, flag) {
			t.Errorf("contract send --help missing flag %q", flag)
		}
	}
}

// TestContractSendUnlimitedWithoutYesRejected pins the §4.2 deliberate-ack ceremony at
// the CLI boundary: --unlimited acknowledges an infinite allowance and REQUIRES --yes
// (exactly as `token approve --unlimited` does, token.go). Passing --unlimited alone is a
// usage error (exit 2) raised BEFORE the service opens — so an agent never burns a
// signing attempt learning the requirement, and `--yes` alone can never carry the ack.
func TestContractSendUnlimitedWithoutYesRejected(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "contract", "send", "0x000000000000000000000000000000000000bEEF",
		"approve", "0x000000000000000000000000000000000000A77a",
		"115792089237316195423570985008687907853269984665640564039457584007913129639935",
		"--sig", "approve(address,uint256)", "--unlimited")
	if code != int(domain.ExitUsage) {
		t.Fatalf("contract send --unlimited without --yes exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "unlimited_unacked") {
		t.Errorf("--unlimited-without-yes denial missing usage.unlimited_unacked:\n%s", stderr)
	}
}

func TestContractAddArgCount(t *testing.T) {
	isolateEnv(t)
	// contract add needs <alias> <0xaddr>.
	if _, _, code := execCLI(t, "contract", "add", "stk"); code != int(domain.ExitUsage) {
		t.Fatalf("contract add (one arg) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestContractAddBothABISourcesRejected(t *testing.T) {
	isolateEnv(t)
	// --abi and --abi-stdin are mutually exclusive (a frontend usage error, exit 2).
	_, _, code := execCLI(t, "contract", "add", "stk", "0x000000000000000000000000000000000000bEEF",
		"--abi", "/nonexistent.json", "--abi-stdin")
	if code != int(domain.ExitUsage) {
		t.Fatalf("contract add --abi + --abi-stdin exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestContractAddSigRejected(t *testing.T) {
	isolateEnv(t)
	// `contract add` needs a full ABI, not --sig (a single signature cannot describe a
	// whole contract for storage).
	_, _, code := execCLI(t, "contract", "add", "stk", "0x000000000000000000000000000000000000bEEF",
		"--sig", "stake(uint256)")
	if code != int(domain.ExitUsage) {
		t.Fatalf("contract add --sig exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestContractDecodeNoABISource(t *testing.T) {
	isolateEnv(t)
	// decode with no --sig/--abi/--contract ⇒ usage (no ABI to decode against).
	_, _, code := execCLI(t, "contract", "decode", "0xa9059cbb")
	if code != int(domain.ExitUsage) {
		t.Fatalf("contract decode (no ABI) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestContractDecodeBadCalldata(t *testing.T) {
	isolateEnv(t)
	// Non-hex calldata is a usage error (the bytes cannot be parsed).
	_, _, code := execCLI(t, "contract", "decode", "0xZZ", "--sig", "transfer(address,uint256)")
	if code != int(domain.ExitUsage) {
		t.Fatalf("contract decode (bad calldata) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestContractDecodePureRoundTrip(t *testing.T) {
	isolateEnv(t)
	// decode is PURE (no chain, no policy): approve(0x..beef, 999) calldata decodes
	// without dialing — proving the read path never touches the chain client.
	const calldata = "0x095ea7b3" +
		"000000000000000000000000000000000000000000000000000000000000beef" +
		"00000000000000000000000000000000000000000000000000000000000003e7" // 999
	out, _, code := execCLI(t, "contract", "decode", calldata, "--sig", "approve(address,uint256)", "--json")
	if code != 0 {
		t.Fatalf("contract decode (pure) exit = %d, want 0", code)
	}
	if !strings.Contains(out, `"selector": "0x095ea7b3"`) {
		t.Errorf("decode --json missing the approve selector:\n%s", out)
	}
	if !strings.Contains(out, `"999"`) {
		t.Errorf("decode --json missing the decoded amount 999:\n%s", out)
	}
}

func TestContractEncodePure(t *testing.T) {
	isolateEnv(t)
	// encode is PURE: build stake(777) calldata with no chain, no policy. With --sig
	// carrying the method name, the positionals after the contract are the args (no
	// redundant method positional).
	out, _, code := execCLI(t, "contract", "encode", "0x000000000000000000000000000000000000bEEF",
		"777", "--sig", "stake(uint256)", "--json")
	if code != 0 {
		t.Fatalf("contract encode (pure) exit = %d, want 0", code)
	}
	if !strings.Contains(out, "0xa694fc3a") {
		t.Errorf("encode --json missing the stake selector:\n%s", out)
	}
}

func TestContractCallArgCount(t *testing.T) {
	isolateEnv(t)
	// call needs at least the contract positional.
	if _, _, code := execCLI(t, "contract", "call"); code != int(domain.ExitUsage) {
		t.Fatalf("contract call (no args) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// ── policy contract allow/remove ───────────────────────────────────────────────

func TestPolicyContractHelpListsSubcommands(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "policy", "contract", "--help")
	if code != 0 {
		t.Fatalf("policy contract --help exit = %d, want 0", code)
	}
	for _, sub := range []string{"allow", "remove"} {
		if !strings.Contains(out, sub) {
			t.Errorf("policy contract --help missing subcommand %q:\n%s", sub, out)
		}
	}
}

func TestPolicyContractAllowMissingSelector(t *testing.T) {
	isolateEnv(t)
	// --selector is required; the frontend rejects its absence before opening the service.
	_, stderr, code := execCLI(t, "policy", "contract", "allow",
		"0x000000000000000000000000000000000000bEEF", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("policy contract allow (no --selector) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	if !strings.Contains(stderr, "bad_contract_allow") {
		t.Errorf("missing-selector denial code missing bad_contract_allow:\n%s", stderr)
	}
}

func TestPolicyContractAllowArgCount(t *testing.T) {
	isolateEnv(t)
	// allow needs the contract positional.
	if _, _, code := execCLI(t, "policy", "contract", "allow", "--selector", "0xa694fc3a"); code != int(domain.ExitUsage) {
		t.Fatalf("policy contract allow (no contract) exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}
