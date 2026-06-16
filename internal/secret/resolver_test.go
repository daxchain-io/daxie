package secret

import (
	"errors"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// envMap builds a lookupEnv closure from a map.
func envMap(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// fileMap builds a ReadFile closure from a path->contents map.
func fileMap(m map[string]string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		v, ok := m[p]
		if !ok {
			return nil, errors.New("no such file")
		}
		return []byte(v), nil
	}
}

func baseReq() Request {
	return Request{
		EnvFileVar:  "DAXIE_PASSPHRASE_FILE",
		EnvVar:      "DAXIE_PASSPHRASE",
		PromptLabel: "Keystore passphrase: ",
	}
}

func TestAcquirePrecedence(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Request)
		stdin      string
		env        map[string]string
		files      map[string]string
		isTTY      bool
		wantSecret string
		wantSource Source
		wantErr    bool
	}{
		{
			name:       "stdin flag wins over everything",
			mutate:     func(r *Request) { r.StdinFlag = true },
			stdin:      "from-stdin\n",
			env:        map[string]string{"DAXIE_PASSPHRASE": "from-env", "DAXIE_PASSPHRASE_FILE": "/f"},
			files:      map[string]string{"/f": "from-file"},
			wantSecret: "from-stdin",
			wantSource: SourceStdin,
		},
		{
			name:       "file flag beats env-file and env",
			mutate:     func(r *Request) { r.FilePath = "/secret" },
			env:        map[string]string{"DAXIE_PASSPHRASE": "from-env", "DAXIE_PASSPHRASE_FILE": "/other"},
			files:      map[string]string{"/secret": "from-file\n", "/other": "wrong"},
			wantSecret: "from-file",
			wantSource: SourceFile,
		},
		{
			name:       "env-file beats env",
			env:        map[string]string{"DAXIE_PASSPHRASE": "from-env", "DAXIE_PASSPHRASE_FILE": "/ef"},
			files:      map[string]string{"/ef": "from-env-file\n"},
			wantSecret: "from-env-file",
			wantSource: SourceEnvFile,
		},
		{
			name:       "env used when no file sources",
			env:        map[string]string{"DAXIE_PASSPHRASE": "from-env"},
			wantSecret: "from-env",
			wantSource: SourceEnv,
		},
		{
			name:       "empty env value is still a present source",
			env:        map[string]string{"DAXIE_PASSPHRASE": ""},
			wantSecret: "",
			wantSource: SourceEnv,
		},
		{
			name:       "prompt at a TTY when nothing else",
			isTTY:      true,
			wantSecret: "from-prompt",
			wantSource: SourcePrompt,
		},
		{
			name:    "no source, no TTY -> deterministic error (never hangs)",
			isTTY:   false,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Stub the TTY prompt for the prompt-path case.
			origPrompt := promptFunc
			promptFunc = func(label string) ([]byte, error) { return []byte("from-prompt"), nil }
			t.Cleanup(func() { promptFunc = origPrompt })

			req := baseReq()
			req.ReadFile = fileMap(tc.files)
			if tc.mutate != nil {
				tc.mutate(&req)
			}
			b, src, err := Acquire(
				req,
				strings.NewReader(tc.stdin),
				envMap(tc.env),
				func() bool { return tc.isTTY },
			)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got secret=%v source=%v", b, src)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if src != tc.wantSource {
				t.Errorf("source = %v, want %v", src, tc.wantSource)
			}
			if string(b.Reveal()) != tc.wantSecret {
				t.Errorf("secret = %q, want %q", b.Reveal(), tc.wantSecret)
			}
		})
	}
}

func TestAcquireStdinConflict(t *testing.T) {
	req := baseReq()
	req.StdinFlag = true
	req.StdinTaken = true
	_, _, err := Acquire(req, strings.NewReader("x"), envMap(nil), func() bool { return false })
	if err == nil {
		t.Fatal("expected a stdin-conflict error")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error is not a *domain.Error: %T", err)
	}
	if !strings.HasPrefix(de.Code, "usage.") {
		t.Errorf("conflict code = %q, want usage.* family", de.Code)
	}
}

func TestAcquireNoSourceNoTTYIsDomainError(t *testing.T) {
	req := baseReq()
	_, _, err := Acquire(req, strings.NewReader(""), envMap(nil), func() bool { return false })
	if err == nil {
		t.Fatal("expected passphrase-required error")
	}
	var de *domain.Error
	if !errors.As(err, &de) {
		t.Fatalf("error is not a *domain.Error: %T", err)
	}
	if de.Code != "keystore.passphrase_required" {
		t.Errorf("code = %q, want keystore.passphrase_required", de.Code)
	}
}

func TestAcquireFileTrailingNewlineStripped(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"pw\n", "pw"},
		{"pw\r\n", "pw"},
		{"pw", "pw"},
		{"pw\n\n", "pw\n"}, // only ONE trailing newline stripped
		{"", ""},
	}
	for _, tc := range tests {
		req := baseReq()
		req.FilePath = "/f"
		req.ReadFile = fileMap(map[string]string{"/f": tc.raw})
		b, _, err := Acquire(req, strings.NewReader(""), envMap(nil), func() bool { return false })
		if err != nil {
			t.Fatalf("raw=%q: %v", tc.raw, err)
		}
		if string(b.Reveal()) != tc.want {
			t.Errorf("raw=%q -> %q, want %q", tc.raw, b.Reveal(), tc.want)
		}
	}
}

func TestAcquireCheckFileInvoked(t *testing.T) {
	called := ""
	wantErr := errors.New("perms bad")
	req := baseReq()
	req.FilePath = "/secret"
	req.ReadFile = fileMap(map[string]string{"/secret": "pw"})
	req.CheckFile = func(p string) error { called = p; return wantErr }

	_, _, err := Acquire(req, strings.NewReader(""), envMap(nil), func() bool { return false })
	if called != "/secret" {
		t.Errorf("CheckFile called with %q, want /secret", called)
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want the CheckFile error propagated", err)
	}
}

func TestAcquireEnvFileCheckedToo(t *testing.T) {
	called := ""
	req := baseReq()
	req.ReadFile = fileMap(map[string]string{"/ef": "pw"})
	req.CheckFile = func(p string) error { called = p; return nil }
	b, src, err := Acquire(
		req,
		strings.NewReader(""),
		envMap(map[string]string{"DAXIE_PASSPHRASE_FILE": "/ef"}),
		func() bool { return false },
	)
	if err != nil {
		t.Fatal(err)
	}
	if src != SourceEnvFile {
		t.Errorf("source = %v, want SourceEnvFile", src)
	}
	if called != "/ef" {
		t.Errorf("CheckFile called with %q, want /ef", called)
	}
	if string(b.Reveal()) != "pw" {
		t.Errorf("secret = %q", b.Reveal())
	}
}

func TestSourceString(t *testing.T) {
	tests := map[Source]string{
		SourceNone:    "none",
		SourceStdin:   "stdin",
		SourceFile:    "file",
		SourceEnvFile: "env-file",
		SourceEnv:     "env",
		SourcePrompt:  "prompt",
	}
	for s, want := range tests {
		if got := s.String(); got != want {
			t.Errorf("Source(%d).String() = %q, want %q", int(s), got, want)
		}
	}
}
