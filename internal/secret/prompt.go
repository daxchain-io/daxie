package secret

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// promptFunc reads a secret from the terminal with echo disabled and prints a
// trailing newline (ReadPassword swallows the user's Enter). It is a package
// variable so tests can stub the actual TTY read without a real terminal.
//
// label is the prompt shown on stderr (so stdout stays clean for piping); the
// returned bytes are the raw secret with the trailing newline already consumed
// by ReadPassword.
var promptFunc = func(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprint(os.Stderr, label)
	pw, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

// IsTerminal reports whether the given reader is an interactive terminal. Only
// *os.File can be a terminal; anything else (a pipe, a bytes.Buffer in tests) is
// not. The cli frontend passes os.Stdin; this is the production isTTY for
// Acquire.
func IsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
