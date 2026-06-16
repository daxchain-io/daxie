// Package domain is the wire contract: the one error taxonomy, the exit-code
// registry, the Principal/event attribution types, and the M0 value types and
// parsers the commands need.
//
// domain imports NOTHING internal (§2.2 rule "contract"). Its only non-stdlib
// import is the go-ethereum value type github.com/ethereum/go-ethereum/common
// (§2.2 rule 3 — geth *value* types only; no behavioral geth package). It does
// no I/O and holds no float field on any wire type (§2.5).
package domain

// ExitCode is the process exit status the CLI returns. The numeric set is kept
// deliberately small and agent-branchable (§5.7); the canonical dotted
// domain.Error.Code string namespaces finer causes *within* one exit number.
//
// Numbers 0..12 are assigned; 13..63 are reserved (never emitted); 64+ are never
// used so daxie never collides with BSD sysexits(3) conventions.
type ExitCode int

const (
	// ExitOK is success. With --wait it means "confirmed"; for receive it means
	// the target was reached. A no-wait `tx send` exits 0 on accepted broadcast
	// (0 != mined there, by design).
	ExitOK ExitCode = 0
	// ExitInternal is a daxie bug or unexpected panic.
	ExitInternal ExitCode = 1
	// ExitUsage is bad input: unknown flag/alias/account, malformed
	// address/amount, --max-fee on a legacy chain, or a confirmation needed with
	// no TTY and no --yes.
	ExitUsage ExitCode = 2
	// ExitPolicyDenied is a guardrail refusal *before* signing.
	ExitPolicyDenied ExitCode = 3
	// ExitAuth is a wrong/missing keystore passphrase or an undecryptable
	// keystore.
	ExitAuth ExitCode = 4
	// ExitInsufficientFunds is balance < value + worst-case gas.
	ExitInsufficientFunds ExitCode = 5
	// ExitNetwork is RPC unreachable/timeout/5xx or a broadcast transport
	// failure (state journaled; resumable).
	ExitNetwork ExitCode = 6
	// ExitReverted is a tx mined with status 0x0 (also: estimation revert with a
	// reason).
	ExitReverted ExitCode = 7
	// ExitTimeoutPending is the "wall is broken or still waiting" class: a wait
	// deadline hit with the tx still pending, receive still listening (NOT a
	// failure), and the policy seal/rollback/admin-auth/state class (all signing
	// halted).
	ExitTimeoutPending ExitCode = 8
	// ExitTxConflict is the nonce/replacement family: replaced, replacement
	// underpriced, speedup/cancel target already mined, nonce too low.
	ExitTxConflict ExitCode = 9
	// ExitNotFound is an unknown reference, OR a read-only config/keystore
	// mutation attempt (the conflict/not-found class).
	ExitNotFound ExitCode = 10
	// ExitState is a state-dir problem: lock-acquisition timeout, corrupt
	// journal beyond tolerance.
	ExitState ExitCode = 11
	// ExitIntegrity is a tamper/misconfig tripwire: endpoint eth_chainId !=
	// declared network, or a counted-tx reservation that has vanished.
	ExitIntegrity ExitCode = 12
)

// String returns the registry name for the exit code (e.g. ExitOK -> "OK"),
// matching the §5.7 table's Name column. An out-of-range code renders as
// "EXIT(<n>)".
func (c ExitCode) String() string {
	switch c {
	case ExitOK:
		return "OK"
	case ExitInternal:
		return "INTERNAL"
	case ExitUsage:
		return "USAGE"
	case ExitPolicyDenied:
		return "POLICY_DENIED"
	case ExitAuth:
		return "AUTH"
	case ExitInsufficientFunds:
		return "INSUFFICIENT_FUNDS"
	case ExitNetwork:
		return "NETWORK"
	case ExitReverted:
		return "REVERTED"
	case ExitTimeoutPending:
		return "TIMEOUT_PENDING"
	case ExitTxConflict:
		return "TX_CONFLICT"
	case ExitNotFound:
		return "NOT_FOUND"
	case ExitState:
		return "STATE"
	case ExitIntegrity:
		return "INTEGRITY"
	default:
		return "EXIT(" + itoa(int(c)) + ")"
	}
}

// itoa is a tiny dependency-free int->decimal (avoids pulling strconv into the
// String fast path; domain stays minimal). Handles the full int range.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	// Work in uint to handle math.MinInt without overflow on negation.
	var u uint
	if neg {
		u = uint(-(n + 1))
		u++
	} else {
		u = uint(n)
	}
	var buf [20]byte
	i := len(buf)
	for u > 0 {
		i--
		buf[i] = byte('0' + u%10)
		u /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
