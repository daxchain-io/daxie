package cli

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// confirm.go holds the destructive-operation confirmation ceremony (§3.9) shared
// by wallet/account export + delete. The contract:
//
//   - --yes set        → proceed (the non-interactive escape hatch).
//   - interactive TTY  → print a red warning and require the operator to TYPE the
//     object NAME exactly; a mismatch aborts.
//   - non-TTY, no --yes → a distinct usage.confirmation_required error (exit 2),
//     NEVER a hang (the same fail-closed discipline as the §3.6 secret resolver).
//
// The ceremony lives in the frontend (it reads the TTY); the service still
// re-resolves the passphrase, so the two guards are independent.

// confirmDestructive runs the ceremony for an operation on `name`. `verb` is a
// human phrase like "delete wallet" or "export the mnemonic for". It returns nil
// to proceed or a domain.Error to abort.
func confirmDestructive(cmd *cobra.Command, rs *rootState, name, verb string) error {
	if rs.flags.Yes {
		return nil
	}

	// Interactive only when stdin is a real terminal. (A piped/redirected stdin —
	// the agent/CI case — is non-interactive: require --yes.)
	if !stdinIsTTY() {
		return domain.Newf("usage.confirmation_required",
			"refusing to %s %q without confirmation: pass --yes (no TTY to confirm interactively)", verb, name)
	}

	// TTY ceremony: warn loudly, then require the exact name typed back.
	errw := cmd.ErrOrStderr()
	_, _ = errw.Write([]byte("WARNING: about to " + verb + " " + strconv.Quote(name) + ".\n"))
	_, _ = errw.Write([]byte("This is irreversible. Type the name to confirm: "))

	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	typed := strings.TrimRight(line, "\r\n")
	if typed != name {
		return domain.Newf("usage.confirmation_required",
			"confirmation mismatch: typed %q, expected %q — aborted", typed, name)
	}
	return nil
}

// stdinIsTTY reports whether stdin is an interactive terminal. The cli frontend
// (not the determinism-guarded core) may inspect the TTY directly.
func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// utoa32 formats an int (an account/wallet count or index) as decimal for human
// tables. It wraps strconv to keep the call sites terse.
func utoa32(n int) string { return strconv.Itoa(n) }

// utoa64 formats a uint64 (a policy nonce / watermark) as decimal for human tables.
func utoa64(n uint64) string { return strconv.FormatUint(n, 10) }
