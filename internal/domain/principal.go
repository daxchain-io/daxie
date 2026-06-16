package domain

// Principal is the WHO behind a call — the attribution that becomes the journal
// Source (§2.4, §6.4). In v1 the CLI sets {Kind:"local", Label:"cli"} and the
// MCP frontend sets Label:"mcp"; the v1.1 HTTP daemon will fill it from a bearer
// token. The core never invents a Principal — the frontend supplies it.
type Principal struct {
	Kind  string `json:"kind"`  // "local" in v1
	Label string `json:"label"` // "cli" | "mcp" — journal Source attribution
}

// LocalCLI is the Principal the Cobra frontend uses for every command.
func LocalCLI() Principal { return Principal{Kind: "local", Label: "cli"} }

// LocalMCP is the Principal the (M11) MCP frontend will use. Provided now so the
// attribution value is defined in one place.
func LocalMCP() Principal { return Principal{Kind: "local", Label: "mcp"} }
