package cli

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
)

// ceremony.go owns the §3.5 "display-once + recorded-it proof" for `wallet
// create`. A fresh mnemonic is the SOLE backup of a wallet and is shown exactly
// once; this ceremony makes the operator prove they recorded it before the
// command returns.
//
// The three paths (§3.5):
//
//   - TTY, no --yes (the interactive default): show the mnemonic once on stderr,
//     CLEAR the screen, then require the operator to re-enter two RANDOMLY chosen
//     word positions. A mismatch aborts (nothing is re-printed). The success line
//     does NOT re-print the mnemonic — it was shown once.
//   - --yes (the non-interactive escape hatch, the agent/CI case): the mnemonic is
//     emitted ONCE in the command result (the JSON object with "sensitive":true,
//     or the human RECORD-THIS block) and never again. The echo is gated on --yes.
//   - no TTY, no --yes: refuse with a distinct usage.confirmation_required error —
//     a fresh mnemonic must never be dumped to a non-interactive stream without the
//     explicit --yes acknowledgement, and there is no terminal to run the proof on.
//
// The ceremony is a FRONTEND concern (it reads the TTY and clears the screen); the
// service already returned the mnemonic once in the result. This file never logs,
// journals, or files the mnemonic — it writes the words to stderr for the operator
// to read, then clears them.

// mnemonicDisplay is the decision the create command acts on after the ceremony.
type mnemonicDisplay struct {
	// echoInResult is true when the success output should emit the mnemonic once
	// (the --yes non-interactive path). False after the interactive ceremony, where
	// the mnemonic was already shown once on stderr and must not be repeated.
	echoInResult bool
}

// preflightMnemonicDisplay decides — BEFORE the wallet is created — whether a
// fresh mnemonic can be shown at all, so a refusal happens before any secret is
// persisted (a created-but-undisplayable wallet would be unrecoverable). It
// returns the refusal error for the no-TTY/no-yes case; otherwise nil. The actual
// show + recorded-it proof runs after creation in mnemonicCeremony.
func preflightMnemonicDisplay(yes bool) error {
	if yes {
		return nil // --yes: the result renderer will emit it once.
	}
	if !stdinIsTTY() {
		return domain.New("usage.confirmation_required",
			"refusing to create a wallet whose new mnemonic cannot be shown safely: run interactively "+
				"(the §3.5 recorded-it proof) or pass --yes to emit it once non-interactively (then record it immediately)")
	}
	return nil
}

// mnemonicCeremony runs the §3.5 ceremony for a freshly created wallet. mnemonic
// and bip39Pass are the one-time secrets the service returned. On the interactive
// path it shows them on stderr, clears the screen, and verifies the recorded-it
// proof; on --yes it defers the single echo to the result renderer. Callers MUST
// have passed preflightMnemonicDisplay before creating the wallet, so the no-TTY/
// no-yes refusal already happened (this function still re-checks, defensively).
// errw is the command's stderr.
func mnemonicCeremony(errw io.Writer, yes bool, mnemonic, bip39Pass string) (mnemonicDisplay, error) {
	if yes {
		// Non-interactive acknowledged path: the result renderer emits the mnemonic
		// once (JSON sensitive=true, or the human RECORD block).
		return mnemonicDisplay{echoInResult: true}, nil
	}

	if !stdinIsTTY() {
		// Defensive: preflight should have caught this before creation.
		return mnemonicDisplay{}, domain.New("usage.confirmation_required",
			"refusing to display a new mnemonic without confirmation: run interactively (the recorded-it proof) "+
				"or pass --yes to emit it once non-interactively (then record it immediately)")
	}

	// Interactive TTY ceremony: show once, clear, prove.
	if err := showMnemonicOnce(errw, mnemonic, bip39Pass); err != nil {
		return mnemonicDisplay{}, err
	}
	words := strings.Fields(mnemonic)
	if len(words) < 2 {
		// Defensive: a valid BIP-39 mnemonic is 12+ words; this never trips in
		// practice but keeps the function total.
		return mnemonicDisplay{}, domain.New("usage.confirmation_required", "cannot run the recorded-it proof on a malformed mnemonic")
	}
	a, b, err := twoDistinctPositions(len(words))
	if err != nil {
		return mnemonicDisplay{}, err
	}
	if err := verifyRecordedProof(errw, os.Stdin, words, a, b); err != nil {
		return mnemonicDisplay{}, err
	}
	// Shown once already; the success line must not repeat it.
	return mnemonicDisplay{echoInResult: false}, nil
}

// showMnemonicOnce prints the mnemonic (and any BIP-39 passphrase) to errw with a
// loud RECORD notice, waits for the operator to acknowledge, then clears the
// screen so the words do not linger in scrollback for a casual shoulder-surfer.
func showMnemonicOnce(errw io.Writer, mnemonic, bip39Pass string) error {
	_, _ = io.WriteString(errw, "\n")
	_, _ = io.WriteString(errw, "RECORD THIS MNEMONIC — it is the ONLY backup and is shown only once:\n\n")
	_, _ = io.WriteString(errw, "    "+mnemonic+"\n")
	if bip39Pass != "" {
		_, _ = io.WriteString(errw, "    bip39-passphrase: "+bip39Pass+"\n")
	}
	_, _ = io.WriteString(errw, "\nWrite it down now. Press Enter when you have recorded it; the screen will clear.")

	// Wait for the operator to acknowledge before clearing.
	r := bufio.NewReader(os.Stdin)
	_, _ = r.ReadString('\n')

	clearScreen(errw)
	return nil
}

// verifyRecordedProof requires the operator to type back the words at the two
// (caller-chosen, distinct) positions a and b. A mismatch aborts with
// usage.confirmation_required. The comparison is case-insensitive on the trimmed
// token (the operator may capitalize), but the stored mnemonic is the canonical
// lowercase English wordlist. Selection is separated from verification so the
// proof is deterministically testable.
func verifyRecordedProof(errw io.Writer, stdin io.Reader, words []string, a, b int) error {
	_, _ = io.WriteString(errw, "Recorded-it check: re-enter the requested words to confirm you wrote them down.\n")
	reader := bufio.NewReader(stdin)
	for _, pos := range []int{a, b} {
		if pos < 0 || pos >= len(words) {
			return domain.New("usage.confirmation_required", "internal: requested word position out of range")
		}
		_, _ = fmt.Fprintf(errw, "  word #%d: ", pos+1) // 1-based for humans
		line, _ := reader.ReadString('\n')
		typed := strings.ToLower(strings.TrimSpace(line))
		if typed != words[pos] {
			return domain.Newf("usage.confirmation_required",
				"word #%d did not match — aborting so you re-run create and record the mnemonic carefully", pos+1)
		}
	}
	_, _ = io.WriteString(errw, "Confirmed.\n")
	return nil
}

// twoDistinctPositions returns two distinct uniformly-random indexes in [0, n)
// using crypto/rand (the frontend is not determinism-guarded). a < b for stable
// prompting order. n is the word count (>= 2, enforced by the caller).
func twoDistinctPositions(n int) (int, int, error) {
	a, err := randIntn(n)
	if err != nil {
		return 0, 0, err
	}
	b, err := randIntn(n)
	if err != nil {
		return 0, 0, err
	}
	for b == a {
		b, err = randIntn(n)
		if err != nil {
			return 0, 0, err
		}
	}
	if a > b {
		a, b = b, a
	}
	return a, b, nil
}

// randIntn returns a uniform random int in [0, n) from crypto/rand.
func randIntn(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, domain.Newf("state.corrupt", "cannot read entropy for the recorded-it proof: %v", err)
	}
	return int(v.Int64()), nil
}

// clearScreen emits the ANSI clear-screen + cursor-home sequence. Best-effort: on
// a terminal that ignores it, the words remain in scrollback (the operator was
// told to record them) but the proof still runs. The sequence goes to the same
// stream the mnemonic was shown on (stderr), so stdout stays clean.
func clearScreen(w io.Writer) {
	// ESC[2J clears the screen, ESC[3J clears scrollback (xterm), ESC[H homes the
	// cursor.
	_, _ = io.WriteString(w, "\x1b[3J\x1b[2J\x1b[H")
}
