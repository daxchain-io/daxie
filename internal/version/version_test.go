package version

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGetReturnsVars(t *testing.T) {
	// Save and restore the package vars so the test does not leak mutation.
	origV, origC, origD := Version, Commit, Date
	t.Cleanup(func() { Version, Commit, Date = origV, origC, origD })

	Version, Commit, Date = "1.2.3", "abc123", "2026-06-16T00:00:00Z"
	got := Get()
	if got.Version != "1.2.3" || got.Commit != "abc123" || got.Date != "2026-06-16T00:00:00Z" {
		t.Fatalf("Get() = %+v, want injected values", got)
	}
}

func TestDefaultSentinels(t *testing.T) {
	// The package-level defaults must be the dev sentinels (the linker has not
	// run in `go test`). We assert the literals so a typo in the default is
	// caught.
	if Version != "dev" {
		t.Errorf("default Version = %q, want %q", Version, "dev")
	}
	if Commit != "none" {
		t.Errorf("default Commit = %q, want %q", Commit, "none")
	}
	if Date != "unknown" {
		t.Errorf("default Date = %q, want %q", Date, "unknown")
	}
}

func TestInfoJSONShape(t *testing.T) {
	b, err := json.Marshal(Info{Version: "v", Commit: "c", Date: "d"})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"version":"v","commit":"c","date":"d"}`
	if string(b) != want {
		t.Fatalf("Marshal = %s, want %s", b, want)
	}
}

func TestInfoString(t *testing.T) {
	s := Info{Version: "1.0.0", Commit: "deadbeef", Date: "2026-01-01"}.String()
	for _, want := range []string{"daxie", "1.0.0", "deadbeef", "2026-01-01"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() = %q, missing %q", s, want)
		}
	}
}
