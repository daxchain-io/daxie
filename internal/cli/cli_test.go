package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// execCLI runs the cli with explicit args and captured streams through the real
// Execute funnel (newRootCmd + mapError), returning stdout, stderr, and the exit
// code. This is the smoke harness — it exercises the actual error→exit mapping.
func execCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	rs := &rootState{}
	ctx := context.Background()
	root := newRootCmd(ctx, rs)
	root.SetArgs(args)
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	err := root.ExecuteContext(ctx)
	code = mapError(&errBuf, rs.flags.Mode(), err)
	return outBuf.String(), errBuf.String(), code
}

// isolateEnv points every state class at a temp dir so tests never touch the
// developer's real config/keystore. The config dir holds a minimal config.toml
// so Open succeeds; it returns the config dir so set/get tests can re-read the
// written file. (Each subtest gets its own dir via t.TempDir.)
func isolateEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("schema = 1\n"), 0o600); err != nil {
		t.Fatalf("seed config.toml: %v", err)
	}
	t.Setenv("DAXIE_CONFIG", dir)
	t.Setenv("DAXIE_KEYSTORE", t.TempDir())
	t.Setenv("DAXIE_STATE_DIR", t.TempDir())
	t.Setenv("DAXIE_CACHE_DIR", t.TempDir())
	return dir
}

func TestVersion(t *testing.T) {
	isolateEnv(t)

	t.Run("human", func(t *testing.T) {
		out, _, code := execCLI(t, "version")
		if code != int(domain.ExitOK) {
			t.Fatalf("exit = %d, want 0", code)
		}
		if !strings.HasPrefix(out, "daxie ") {
			t.Errorf("version human output %q does not start with 'daxie '", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out, _, code := execCLI(t, "version", "--json")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		var info struct {
			Version string `json:"version"`
			Commit  string `json:"commit"`
			Date    string `json:"date"`
		}
		if err := json.Unmarshal([]byte(out), &info); err != nil {
			t.Fatalf("version --json not valid JSON: %v (%q)", err, out)
		}
		if info.Version == "" {
			t.Error("version field empty")
		}
	})

	// The version string IS the essential output of `daxie version`, so --quiet
	// must NOT suppress it (it trims only non-essential chatter). Regression guard
	// for the bug where the human line went through render.Line and vanished.
	t.Run("quiet still prints (essential output)", func(t *testing.T) {
		out, _, code := execCLI(t, "version", "--quiet")
		if code != int(domain.ExitOK) {
			t.Fatalf("exit = %d, want 0", code)
		}
		if !strings.HasPrefix(out, "daxie ") {
			t.Errorf("version --quiet output %q does not start with 'daxie ' — --quiet must not suppress essential output", out)
		}
	})

	t.Run("quiet json still prints", func(t *testing.T) {
		out, _, code := execCLI(t, "version", "--quiet", "--json")
		if code != int(domain.ExitOK) {
			t.Fatalf("exit = %d, want 0", code)
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("version --quiet --json produced no output")
		}
	})
}

func TestConvertCmd(t *testing.T) {
	isolateEnv(t)

	tests := []struct {
		name     string
		args     []string
		wantOut  string
		wantCode int
	}{
		{"eth to wei", []string{"convert", "1.5eth", "wei"}, "1500000000000000000\n", 0},
		{"wei to gwei", []string{"convert", "30000000000wei", "gwei"}, "30\n", 0},
		{"eth to gwei", []string{"convert", "1eth", "gwei"}, "1000000000\n", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, code := execCLI(t, tt.args...)
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d", code, tt.wantCode)
			}
			if out != tt.wantOut {
				t.Errorf("out = %q, want %q", out, tt.wantOut)
			}
		})
	}
}

func TestConvertCmdJSON(t *testing.T) {
	isolateEnv(t)
	out, _, code := execCLI(t, "convert", "1eth", "gwei", "--json")
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	var res struct {
		Wei   string `json:"wei"`
		From  string `json:"from"`
		To    string `json:"to"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("not valid JSON: %v (%q)", err, out)
	}
	if res.Value != "1000000000" {
		t.Errorf("value = %q, want 1000000000", res.Value)
	}
	if res.From != "eth" || res.To != "gwei" {
		t.Errorf("from/to = %q/%q, want eth/gwei", res.From, res.To)
	}
}

// Bad unit → exit 2 (USAGE) with a structured error on stderr in --json mode.
func TestConvertBadUnitExit2(t *testing.T) {
	isolateEnv(t)
	_, stderr, code := execCLI(t, "convert", "1eth", "foo", "--json")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
			Exit int    `json:"exit"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(stderr), &env); err != nil {
		t.Fatalf("error envelope not JSON: %v (%q)", err, stderr)
	}
	if env.Error.Exit != 2 {
		t.Errorf("envelope exit = %d, want 2", env.Error.Exit)
	}
	if !strings.HasPrefix(env.Error.Code, "usage.") {
		t.Errorf("code = %q, want usage.*", env.Error.Code)
	}
}

// Unknown command → exit 2 (USAGE), classified by the funnel (non-domain error).
func TestUnknownCommandExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "no-such-command")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// Unknown flag → exit 2 (USAGE).
func TestUnknownFlagExit2(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "version", "--frobnicate")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

func TestConfigList(t *testing.T) {
	isolateEnv(t)

	t.Run("human", func(t *testing.T) {
		out, _, code := execCLI(t, "config", "list")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if !strings.Contains(out, "defaults.network") {
			t.Errorf("config list missing defaults.network:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		out, _, code := execCLI(t, "config", "list", "--json")
		if code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		var kvs []struct {
			Key string `json:"key"`
		}
		if err := json.Unmarshal([]byte(out), &kvs); err != nil {
			t.Fatalf("config list --json not valid JSON: %v (%q)", err, out)
		}
		found := false
		for _, kv := range kvs {
			if kv.Key == "defaults.network" {
				found = true
			}
		}
		if !found {
			t.Errorf("config list --json missing defaults.network")
		}
	})
}

// config set then get round-trips; unknown key get → exit 10 (ref.not_found).
func TestConfigSetGetRoundTrip(t *testing.T) {
	isolateEnv(t)

	_, _, code := execCLI(t, "config", "set", "defaults.network", "sepolia")
	if code != 0 {
		t.Fatalf("config set exit = %d, want 0", code)
	}
	out, _, code := execCLI(t, "config", "get", "defaults.network")
	if code != 0 {
		t.Fatalf("config get exit = %d, want 0", code)
	}
	if strings.TrimSpace(out) != "sepolia" {
		t.Errorf("config get = %q, want sepolia", strings.TrimSpace(out))
	}
}

func TestConfigGetUnknownExit10(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "config", "get", "no.such.key")
	if code != int(domain.ExitNotFound) {
		t.Fatalf("exit = %d, want %d (NOT_FOUND)", code, domain.ExitNotFound)
	}
}

// Rejected policy.* set → exit 2 (USAGE).
func TestConfigSetPolicyRejected(t *testing.T) {
	isolateEnv(t)
	_, _, code := execCLI(t, "config", "set", "policy.max-tx", "1")
	if code != int(domain.ExitUsage) {
		t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
	}
}

// The §4.6 anchor Viper carve-out regression: NO DAXIE_POLICY_* env var and NO
// flag can reach the policy anchor. Even with a battery of policy-shaped env vars
// set, `policy verify` against a pristine (no-anchor) install reports the opt-in
// state (exit 0) rather than picking up an env-injected verify key, and `config
// set/get policy.*` are rejected. This is the cli-layer twin of
// internal/config/anchor_test.go's TestAnchorCarveOut.
func TestPolicyAnchorCarveOut(t *testing.T) {
	isolateEnv(t)
	t.Setenv("DAXIE_POLICY_VERIFY_KEY", "ed25519:ATTACKER")
	t.Setenv("DAXIE_POLICY_ANCHOR", "/tmp/attacker-anchor.json")
	t.Setenv("DAXIE_POLICY_MAX_TX", "1000000000000000000000")

	// No on-disk anchor ⇒ opt-in; the env cannot synthesize one ⇒ verify exit 0.
	if _, _, code := execCLI(t, "policy", "verify"); code != int(domain.ExitOK) {
		t.Errorf("policy verify with DAXIE_POLICY_* set exit = %d, want 0 (env cannot inject an anchor)", code)
	}
	// config still refuses the policy.* subtree (it is never a Viper key).
	if _, _, code := execCLI(t, "config", "set", "policy.verify_key", "ed25519:x"); code != int(domain.ExitUsage) {
		t.Errorf("config set policy.verify_key exit = %d, want 2 (USAGE)", code)
	}
}

func TestCompletion(t *testing.T) {
	isolateEnv(t)
	for _, sh := range []string{"bash", "zsh", "fish"} {
		t.Run(sh, func(t *testing.T) {
			out, _, code := execCLI(t, "completion", sh)
			if code != 0 {
				t.Fatalf("completion %s exit = %d, want 0", sh, code)
			}
			if len(out) == 0 {
				t.Errorf("completion %s produced no script", sh)
			}
		})
	}
	t.Run("unknown shell exit 2", func(t *testing.T) {
		_, _, code := execCLI(t, "completion", "powershell")
		if code != int(domain.ExitUsage) {
			t.Fatalf("exit = %d, want %d (USAGE)", code, domain.ExitUsage)
		}
	})
}
