package secret

import (
	"io"
	"os"

	"github.com/daxchain-io/daxie/internal/domain"
)

// Source identifies where a resolved secret came from, for error messages and to
// let callers branch on the §3.6 precedence outcome.
type Source int

const (
	// SourceNone means no secret was acquired.
	SourceNone Source = iota
	// SourceStdin: read from stdin because --*-stdin was set.
	SourceStdin
	// SourceFile: read from the path given by --*-file.
	SourceFile
	// SourceEnvFile: read from the file named by the *_FILE env var.
	SourceEnvFile
	// SourceEnv: read directly from the env var value.
	SourceEnv
	// SourcePrompt: read interactively from the TTY.
	SourcePrompt
)

// String renders the source for diagnostics.
func (s Source) String() string {
	switch s {
	case SourceStdin:
		return "stdin"
	case SourceFile:
		return "file"
	case SourceEnvFile:
		return "env-file"
	case SourceEnv:
		return "env"
	case SourcePrompt:
		return "prompt"
	default:
		return "none"
	}
}

// Request describes one secret acquisition. The resolver is generic over the
// flag/env names so the keystore passphrase (§3.6), the admin passphrase (§3.7),
// and the mnemonic/raw-key inputs reuse it with different names.
type Request struct {
	// StdinFlag is true when the --*-stdin flag was set; the value is read from r.
	StdinFlag bool
	// FilePath is the --*-file value ("" when unset). Read via ReadFile/CheckFile.
	FilePath string
	// EnvFileVar is the name of the *_FILE env var, e.g. "DAXIE_PASSPHRASE_FILE".
	EnvFileVar string
	// EnvVar is the name of the direct env var, e.g. "DAXIE_PASSPHRASE".
	EnvVar string
	// PromptLabel is shown at a TTY when no other source is present, e.g.
	// "Keystore passphrase: ".
	PromptLabel string
	// StdinTaken indicates stdin is already claimed by a command payload, so
	// reading the secret from stdin would be ambiguous. With StdinFlag set this
	// is a hard conflict (Daxie errors rather than guessing, §3.6).
	StdinTaken bool

	// CheckFile, if non-nil, is called on the resolved file path (from FilePath
	// or the *_FILE env var) to enforce the §7.9 permission rule before reading.
	// secret stays a pure leaf by not importing fsx directly; the caller (service)
	// injects fsx.CheckPerms here. Nil means no permission check (used in tests
	// and by callers that have already checked).
	CheckFile func(path string) error
	// ReadFile, if non-nil, reads a file's bytes. Defaults to os.ReadFile when
	// nil. Injectable so the resolver can be unit-tested without touching disk.
	ReadFile func(path string) ([]byte, error)
}

// Acquire applies the §3.6 precedence (stdin > file > *_FILE-env > env > prompt)
// and returns the secret, the source it came from, and an error. It NEVER hangs:
// when no source is present and the terminal is not interactive, it returns a
// distinct domain.Error (keystore.passphrase_required) rather than blocking on a
// read.
//
//   - r is the stdin reader (os.Stdin in production, a buffer in tests).
//   - lookupEnv is os.LookupEnv in production, injected in tests.
//   - isTTY reports whether interactive prompting is possible (term.IsTerminal in
//     production); when false and no other source exists, the prompt is skipped
//     and a deterministic error is returned.
//
// On a stdin conflict (StdinFlag && StdinTaken) it returns a usage error.
func Acquire(req Request, r io.Reader, lookupEnv func(string) (string, bool), isTTY func() bool) (*Bytes, Source, error) {
	readFile := req.ReadFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}

	// 1. --*-stdin (explicit flag beats everything).
	if req.StdinFlag {
		if req.StdinTaken {
			return nil, SourceNone, domain.New(
				"usage.stdin_conflict",
				"cannot read the secret from stdin: stdin is already consumed by the command payload; use a --*-file or *_FILE env var instead",
			)
		}
		raw, err := io.ReadAll(r)
		if err != nil {
			return nil, SourceNone, domain.Newf("usage.stdin_read", "failed to read secret from stdin: %v", err)
		}
		return New(trimTrailingNewline(raw)), SourceStdin, nil
	}

	// 2. --*-file.
	if req.FilePath != "" {
		b, err := readSecretFile(req, readFile, req.FilePath)
		if err != nil {
			return nil, SourceNone, err
		}
		return New(b), SourceFile, nil
	}

	// 3. *_FILE env var (the recommended unattended channel).
	if req.EnvFileVar != "" {
		if path, ok := lookupEnv(req.EnvFileVar); ok && path != "" {
			b, err := readSecretFile(req, readFile, path)
			if err != nil {
				return nil, SourceNone, err
			}
			return New(b), SourceEnvFile, nil
		}
	}

	// 4. direct env var (documented least-safe).
	if req.EnvVar != "" {
		if val, ok := lookupEnv(req.EnvVar); ok {
			// An env var value is used verbatim (no newline trimming — the user
			// set it deliberately; a *_FILE channel is the one that strips \n).
			return NewString(val), SourceEnv, nil
		}
	}

	// 5. interactive prompt — only at a TTY.
	if isTTY != nil && isTTY() {
		pw, err := promptFunc(req.PromptLabel)
		if err != nil {
			return nil, SourceNone, domain.Newf("keystore.prompt_failed", "failed to read secret from terminal: %v", err)
		}
		return New(pw), SourcePrompt, nil
	}

	// 6. none + no TTY: deterministic error, never a hang.
	return nil, SourceNone, domain.New(
		"keystore.passphrase_required",
		"a passphrase is required but no source was provided and stdin is not a terminal; "+
			"set it via --*-stdin, --*-file <path>, "+req.EnvFileVar+" (a file path), or "+req.EnvVar,
	)
}

// readSecretFile checks perms (if a checker is injected), reads, and strips one
// trailing newline (§3.6 file hygiene).
func readSecretFile(req Request, readFile func(string) ([]byte, error), path string) ([]byte, error) {
	if req.CheckFile != nil {
		if err := req.CheckFile(path); err != nil {
			return nil, err
		}
	}
	b, err := readFile(path)
	if err != nil {
		return nil, domain.Newf("keystore.passphrase_file_error", "failed to read passphrase file %q: %v", path, err)
	}
	return trimTrailingNewline(b), nil
}

// trimTrailingNewline strips exactly one trailing "\n" or "\r\n" (K8s Secrets and
// `echo` append one; §3.6). It returns a copy so the buffer the secret owns is
// independent of the source slice.
func trimTrailingNewline(b []byte) []byte {
	out := b
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
		if n := len(out); n > 0 && out[n-1] == '\r' {
			out = out[:n-1]
		}
	}
	// Copy so we own the memory (the source may be a reused buffer / mmap).
	cp := make([]byte, len(out))
	copy(cp, out)
	return cp
}
