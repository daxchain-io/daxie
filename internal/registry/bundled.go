package registry

import "github.com/ethereum/go-ethereum/common"

// bundledMajors is the compiled-in token set (§7.8): the well-known ERC-20 majors
// (USDC/USDT/WETH/DAI) per network, pinned to canonical addresses. These are NOT
// written to any registry/<network>.json file — they are part of the binary. A
// same-alias file entry OVERRIDES the bundled one (§7.8 "a same-alias file entry
// overrides the bundled one"), so an operator who registers a different USDC for a
// network wins over the compiled-in default. Per-network because the same alias maps
// to different addresses on mainnet vs an L2/testnet.
//
// Anti-spoofing note: bundled entries are part of the registry's "known" set —
// Resolve checks file entries then this table and then ERRORS; it never falls back
// to an on-chain symbol() lookup (symbol spoofing is free, §7.8 / requirements §2).
//
// Sepolia: only the entries whose testnet deployments are canonical-universal are
// bundled. USDC is Circle's published Sepolia deployment; WETH is the canonical
// Sepolia WETH9. USDT/DAI have no single canonical Sepolia deployment, so they are
// OMITTED rather than guessed — a registry miss is recoverable via `token add`, but a
// wrong bundled address is a silent fund-loss footgun (fail honest, never fabricate).
//
// Aliases are stored canonicalized (lowercase, §3.1 grammar) so they collide and
// resolve case-insensitively with file entries.
var bundledMajors = map[string][]Token{
	"mainnet": {
		{Alias: "usdc", Address: common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), Kind: KindERC20, Decimals: 6, Symbol: "USDC"},
		{Alias: "usdt", Address: common.HexToAddress("0xdAC17F958D2ee523a2206206994597C13D831ec7"), Kind: KindERC20, Decimals: 6, Symbol: "USDT"},
		{Alias: "weth", Address: common.HexToAddress("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"), Kind: KindERC20, Decimals: 18, Symbol: "WETH"},
		{Alias: "dai", Address: common.HexToAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F"), Kind: KindERC20, Decimals: 18, Symbol: "DAI"},
	},
	"sepolia": {
		// Circle's published Sepolia USDC + the canonical Sepolia WETH9. USDT/DAI
		// testnet deployments are not canonical-universal — omitted (see doc above).
		{Alias: "usdc", Address: common.HexToAddress("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"), Kind: KindERC20, Decimals: 6, Symbol: "USDC"},
		{Alias: "weth", Address: common.HexToAddress("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"), Kind: KindERC20, Decimals: 18, Symbol: "WETH"},
	},
}

// bundledFor returns the compiled-in majors for a network, or nil for an unknown
// network (resolution then sees only the file entries).
func bundledFor(network string) []Token { return bundledMajors[network] }

// bundledLookup returns the bundled major for (network, canonAlias) and whether one
// exists. canonAlias must already be canonicalized (lowercase, grammar-valid). Used
// by Add's collision guard and by Resolve's bundled stage.
func bundledLookup(network, canonAlias string) (Token, bool) {
	for _, t := range bundledFor(network) {
		if t.Alias == canonAlias {
			return t, true
		}
	}
	return Token{}, false
}

// mergeBundled overlays file tokens over the bundled set: every bundled major appears
// unless a file token shares its (canonical) alias, in which case the FILE entry wins
// (§7.8 "a same-alias file entry overrides the bundled one"). The result is the full
// known set for a network — bundled majors not shadowed by a file entry, plus every
// file entry. Each row carries Bundled provenance so the caller can show it. The
// result is alias-sorted for a stable listing.
func mergeBundled(network string, fileTokens []Token) []ResolvedToken {
	// Index file aliases so a bundled major with the same alias is suppressed.
	fileAliases := make(map[string]struct{}, len(fileTokens))
	for _, t := range fileTokens {
		fileAliases[t.Alias] = struct{}{}
	}

	out := make([]ResolvedToken, 0, len(fileTokens)+len(bundledFor(network)))
	for _, t := range fileTokens {
		out = append(out, ResolvedToken{Token: t, Bundled: false})
	}
	for _, t := range bundledFor(network) {
		if _, shadowed := fileAliases[t.Alias]; shadowed {
			continue
		}
		out = append(out, ResolvedToken{Token: t, Bundled: true})
	}
	sortResolved(out)
	return out
}
