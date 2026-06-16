package domain

import (
	"encoding/json"
	"testing"
)

func TestPrincipalConstructors(t *testing.T) {
	if p := LocalCLI(); p.Kind != "local" || p.Label != "cli" {
		t.Errorf("LocalCLI() = %+v, want {local, cli}", p)
	}
	if p := LocalMCP(); p.Kind != "local" || p.Label != "mcp" {
		t.Errorf("LocalMCP() = %+v, want {local, mcp}", p)
	}
}

func TestPrincipalJSON(t *testing.T) {
	b, err := json.Marshal(LocalCLI())
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"kind":"local","label":"cli"}` {
		t.Errorf("Principal JSON = %s", b)
	}
}
