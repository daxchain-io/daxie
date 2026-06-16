package render

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// JSON mode marshals the value and never calls the human func.
func TestResultJSONMode(t *testing.T) {
	var buf bytes.Buffer
	humanCalled := false
	err := Result(&buf, Mode{JSON: true},
		map[string]string{"version": "dev", "commit": "none"},
		func(io.Writer) { humanCalled = true },
	)
	if err != nil {
		t.Fatalf("Result: %v", err)
	}
	if humanCalled {
		t.Error("human func called in JSON mode")
	}
	var got map[string]string
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output not valid JSON: %v (%q)", err, buf.String())
	}
	if got["version"] != "dev" {
		t.Errorf("version = %q, want dev", got["version"])
	}
}

// Human mode calls the human func and does not emit JSON.
func TestResultHumanMode(t *testing.T) {
	var buf bytes.Buffer
	err := Result(&buf, Mode{},
		map[string]string{"version": "dev"},
		func(w io.Writer) { _, _ = io.WriteString(w, "daxie dev\n") },
	)
	if err != nil {
		t.Fatalf("Result: %v", err)
	}
	if got := buf.String(); got != "daxie dev\n" {
		t.Errorf("human output = %q, want %q", got, "daxie dev\n")
	}
	if strings.Contains(buf.String(), "{") {
		t.Error("human mode emitted JSON")
	}
}

// The JSON error envelope shape matches §5.7: {"error":{code,exit,message,...}}
// and goes to stderr; the returned code matches the error's Exit.
func TestErrorEnvelopeJSON(t *testing.T) {
	var stderr bytes.Buffer
	e := domain.New("usage.bad_flag", "unknown flag --frobnicate")
	code := ErrorEnvelope(&stderr, Mode{JSON: true}, e)

	if code != e.Exit {
		t.Errorf("returned code %d, want %d", code, e.Exit)
	}

	var env struct {
		Error struct {
			Code      string `json:"code"`
			Exit      int    `json:"exit"`
			Message   string `json:"message"`
			Retryable bool   `json:"retryable"`
		} `json:"error"`
	}
	if err := json.Unmarshal(stderr.Bytes(), &env); err != nil {
		t.Fatalf("envelope not valid JSON: %v (%q)", err, stderr.String())
	}
	if env.Error.Code != "usage.bad_flag" {
		t.Errorf("code = %q, want usage.bad_flag", env.Error.Code)
	}
	if env.Error.Exit != int(domain.ExitUsage) {
		t.Errorf("exit = %d, want %d", env.Error.Exit, domain.ExitUsage)
	}
	if env.Error.Message == "" {
		t.Error("message empty")
	}
}

// Human-mode error is a one-line message on stderr carrying the code.
func TestErrorEnvelopeHuman(t *testing.T) {
	var stderr bytes.Buffer
	e := domain.New("ref.not_found", "no such config key: no.such.key")
	code := ErrorEnvelope(&stderr, Mode{}, e)
	if code != domain.ExitNotFound {
		t.Errorf("code = %d, want %d", code, domain.ExitNotFound)
	}
	out := stderr.String()
	if !strings.Contains(out, "no such config key") {
		t.Errorf("stderr %q missing message", out)
	}
	if !strings.Contains(out, "ref.not_found") {
		t.Errorf("stderr %q missing code", out)
	}
	if strings.Contains(out, "{") {
		t.Error("human-mode error emitted JSON")
	}
}

// Quiet must not suppress errors.
func TestErrorEnvelopeQuietStillPrints(t *testing.T) {
	var stderr bytes.Buffer
	e := domain.New("usage.bad", "boom")
	ErrorEnvelope(&stderr, Mode{Quiet: true}, e)
	if stderr.Len() == 0 {
		t.Error("quiet suppressed the error envelope")
	}
}

// Line is suppressed by Quiet; Table aligns columns.
func TestLineQuiet(t *testing.T) {
	var buf bytes.Buffer
	Line(&buf, Mode{Quiet: true}, "noise %d", 1)
	if buf.Len() != 0 {
		t.Errorf("quiet Line wrote %q", buf.String())
	}
	buf.Reset()
	Line(&buf, Mode{}, "hello %s", "world")
	if buf.String() != "hello world\n" {
		t.Errorf("Line = %q", buf.String())
	}
}
