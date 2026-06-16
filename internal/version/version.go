// Package version exposes the build-stamp variables injected by -ldflags at
// release time (§9.4) and a small accessor over them. It imports nothing
// internal and is the one package every frontend may import for build metadata.
package version

// Build-stamp variables. These are overwritten at link time by goreleaser via
//
//	-X github.com/daxchain-io/daxie/internal/version.Version=...
//	-X github.com/daxchain-io/daxie/internal/version.Commit=...
//	-X github.com/daxchain-io/daxie/internal/version.Date=...
//
// The defaults are the dev sentinels used for `go run`/`go build` without
// ldflags so the output is never an empty string.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Info is the JSON-shaped projection of the build stamp. The `daxie version
// --json` command marshals exactly this struct.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// Get returns the current build stamp.
func Get() Info {
	return Info{Version: Version, Commit: Commit, Date: Date}
}

// String returns a single-line human rendering, e.g.
// "daxie dev (commit none, built unknown)".
func (i Info) String() string {
	return "daxie " + i.Version + " (commit " + i.Commit + ", built " + i.Date + ")"
}
