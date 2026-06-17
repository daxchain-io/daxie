package config

import (
	"sort"
	"strings"

	"github.com/daxchain-io/daxie/internal/domain"
)

// rpc.go holds the `daxie rpc` config mutators + accessors + the secret-masking
// and literal-secret heuristic (§6, §7.5, cli-spec §rpc). An ENDPOINT is a named
// connection bound to ONE network; many endpoints per network; one default per
// network (the network's default-rpc); any command overrides per invocation with
// --rpc. mainnet-public + sepolia-public are built-in public defaults. The config
// stores URLs/header values RAW with ${env:}/${file:} references embedded — config
// NEVER resolves them (that happens transiently in service at dial time, §7.5);
// `rpc show`/`rpc list` MASK so a reference is shown as the reference and any
// literal opaque secret segment is reduced to "***".

// builtinEndpointNames is the set of compiled-in public default endpoints. They
// are immutable-as-objects (cannot be removed) but their fields may be overridden.
var builtinEndpointNames = map[string]bool{"mainnet-public": true, "sepolia-public": true}

// EndpointView is the config-owned render shape for one endpoint. URL is already
// MASKED. service re-maps it into domain.RPCRow so the cli never imports config.
type EndpointView struct {
	Name          string
	Network       string
	URL           string // MASKED
	HasHeaders    bool
	HasTLS        bool
	Default       bool // the network's default-rpc points here
	PublicDefault bool // a built-in public endpoint
}

// ListEndpoints returns every merged endpoint (built-in + file), optionally
// filtered to one network, sorted by name, with masked URLs and the default /
// public-default markers set.
func (c *Config) ListEndpoints(network string) []EndpointView {
	out := make([]EndpointView, 0, len(c.RPC))
	for name, e := range c.RPC {
		if network != "" && e.Network != network {
			continue
		}
		out = append(out, c.endpointView(name, e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ShowEndpoint returns one endpoint by name (masked), or ref.not_found.
func (c *Config) ShowEndpoint(name string) (EndpointView, error) {
	e, ok := c.RPC[name]
	if !ok {
		return EndpointView{}, domain.Newf(domain.CodeRefNotFound, "no endpoint named %q", name)
	}
	return c.endpointView(name, e), nil
}

// endpointView builds the masked render shape for one merged endpoint.
func (c *Config) endpointView(name string, e Endpoint) EndpointView {
	v := EndpointView{
		Name:          name,
		Network:       e.Network,
		URL:           MaskSecretRefs(e.URLRef),
		HasHeaders:    len(e.Headers) > 0,
		HasTLS:        e.TLS != nil && (e.TLS.Cert != "" || e.TLS.Key != "" || e.TLS.CA != ""),
		PublicDefault: builtinEndpointNames[name],
	}
	if n, ok := c.Networks[e.Network]; ok && n.DefaultRPC == name {
		v.Default = true
	}
	return v
}

// EndpointsReferencing returns the names of endpoints bound to a network (for the
// `network remove` referencing check). Sorted for deterministic messages.
func (c *Config) EndpointsReferencing(network string) []string {
	var out []string
	for name, e := range c.RPC {
		if e.Network == network {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// AddEndpoint adds a named endpoint bound to a network (cli-spec §rpc add). It
// rejects an invalid name, a collision with an existing endpoint
// (usage.rpc_exists), an empty url or network, and a network that is not known
// (ref.not_found). It runs the literal-secret heuristic: a detected literal secret
// is a WARNING by default and a hard error (usage.literal_secret) when
// strictSecrets is set (§7.5). The url + header values are stored RAW. knownNets
// is the merged network-name set supplied by the caller.
func AddEndpoint(p Paths, name string, e Endpoint, knownNets map[string]bool, strictSecrets bool) (warnings []string, err error) {
	if !validObjectName(name) {
		return nil, invalidName("endpoint", name)
	}
	if e.Network == "" {
		return nil, domain.Newf(domain.CodeUsage+".bad_value",
			"endpoint %q requires --network", name)
	}
	if !knownNets[e.Network] {
		return nil, domain.Newf(domain.CodeRefNotFound,
			"no network named %q; add it with `daxie network add` first", e.Network)
	}
	if e.URLRef == "" {
		return nil, domain.Newf(domain.CodeUsage+".bad_value",
			"endpoint %q requires --url", name)
	}

	if hits := detectLiteralSecret(e.URLRef, e.Headers); len(hits) > 0 {
		if strictSecrets {
			return nil, domain.WithData(
				domain.Newf(domain.CodeUsageLiteralSecret,
					"endpoint %q appears to embed a literal secret (%s); use a ${env:}/${file:} reference, or drop --strict-secrets to add anyway",
					name, strings.Join(hits, ", ")),
				map[string]any{"locations": hits},
			)
		}
		for _, h := range hits {
			warnings = append(warnings, "endpoint "+name+": "+h+
				" looks like a literal secret; it will be stored in config plaintext — prefer a ${env:}/${file:} reference")
		}
	}

	err = mutateRaw(p, func(raw map[string]any) error {
		if endpointExistsRaw(raw, name) || builtinEndpointNames[name] {
			return domain.Newf(domain.CodeUsageRPCExists, "endpoint %q already exists", name)
		}
		base := "rpc." + name + "."
		setNested(raw, base+"network", e.Network)
		setNested(raw, base+"url", e.URLRef) // RAW; ${…} refs stay embedded
		if e.Timeout != 0 {
			setNested(raw, base+"timeout", e.Timeout.String())
		}
		for hk, hv := range e.Headers {
			setNested(raw, base+"headers."+hk, hv) // RAW
		}
		if e.TLS != nil {
			if e.TLS.Cert != "" {
				setNested(raw, base+"tls.cert", e.TLS.Cert)
			}
			if e.TLS.Key != "" {
				setNested(raw, base+"tls.key", e.TLS.Key)
			}
			if e.TLS.CA != "" {
				setNested(raw, base+"tls.ca", e.TLS.CA)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return warnings, nil
}

// UseEndpoint makes an endpoint the default for ITS network: it rewrites
// networks.<endpoint.network>.default-rpc = <name> (cli-spec §rpc use). The
// endpoint's own network field decides which network's default it sets. epNetwork
// is the endpoint's bound network, supplied by the caller (ref.not_found if the
// endpoint is unknown is checked there). A read-only mount maps to
// config.read_only.
func UseEndpoint(p Paths, name, epNetwork string) error {
	return mutateRaw(p, func(raw map[string]any) error {
		setNested(raw, "networks."+epNetwork+".default-rpc", name)
		return nil
	})
}

// RenameEndpoint renames an endpoint (cli-spec §rpc rename). It refuses renaming a
// built-in (usage.builtin_immutable), an unknown source (ref.not_found), a
// collision with an existing/built-in target (usage.rpc_exists), and an invalid
// target name. It re-points any network default-rpc that named the old endpoint.
func RenameEndpoint(p Paths, oldName, newName string) error {
	if builtinEndpointNames[oldName] {
		return domain.Newf(domain.CodeUsageBuiltinImmutable,
			"endpoint %q is built in and cannot be renamed", oldName)
	}
	if !validObjectName(newName) {
		return invalidName("endpoint", newName)
	}
	return mutateRaw(p, func(raw map[string]any) error {
		src := rawSubTable(raw, "rpc", oldName)
		if src == nil {
			return domain.Newf(domain.CodeRefNotFound, "no endpoint named %q", oldName)
		}
		if endpointExistsRaw(raw, newName) || builtinEndpointNames[newName] {
			return domain.Newf(domain.CodeUsageRPCExists, "endpoint %q already exists", newName)
		}
		// Move the table verbatim (preserves headers/tls/timeout + any unknown keys).
		rpcTbl := rawSubTable(raw, "rpc")
		rpcTbl[newName] = src
		delete(rpcTbl, oldName)
		repointDefaultRPC(raw, oldName, newName)
		return nil
	})
}

// RemoveEndpoint removes an endpoint (cli-spec §rpc remove) and clears any network
// default-rpc that pointed at it (reporting which network it cleared). It refuses a
// built-in (usage.builtin_immutable) and an unknown endpoint (ref.not_found). The
// cleared network name is returned via the data map for the caller's result.
func RemoveEndpoint(p Paths, name string) (clearedFor string, err error) {
	if builtinEndpointNames[name] {
		return "", domain.Newf(domain.CodeUsageBuiltinImmutable,
			"endpoint %q is built in and cannot be removed", name)
	}
	err = mutateRaw(p, func(raw map[string]any) error {
		if !endpointExistsRaw(raw, name) {
			return domain.Newf(domain.CodeRefNotFound, "no endpoint named %q", name)
		}
		deleteNested(raw, "rpc."+name)
		clearedFor = repointDefaultRPC(raw, name, "")
		return nil
	})
	if err != nil {
		return "", err
	}
	return clearedFor, nil
}

// repointDefaultRPC walks [networks.*] and, for any default-rpc equal to oldName,
// sets it to newName (a rename) or clears it (newName == "", a remove). It returns
// the name of the LAST network whose default it cleared (for the remove result;
// in practice a default-rpc points at exactly one network).
func repointDefaultRPC(raw map[string]any, oldName, newName string) (clearedFor string) {
	nets := rawSubTable(raw, "networks")
	if nets == nil {
		return ""
	}
	for netName, t := range nets {
		tbl, ok := t.(map[string]any)
		if !ok {
			continue
		}
		if cur, _ := tbl["default-rpc"].(string); cur == oldName {
			if newName == "" {
				delete(tbl, "default-rpc")
				clearedFor = netName
			} else {
				tbl["default-rpc"] = newName
			}
		}
	}
	return clearedFor
}

// endpointExistsRaw reports whether the file defines [rpc.<name>].
func endpointExistsRaw(raw map[string]any, name string) bool {
	return rawSubTable(raw, "rpc", name) != nil
}

// ── masking + the literal-secret heuristic (§7.5) ────────────────────────────

// MaskSecretRefs renders a stored URL/header value for `rpc show`/`rpc list`. A
// ${env:…}/${file:…} REFERENCE is kept verbatim (the reference is not the secret —
// the operator must see WHICH var/file is used). Any other long opaque segment
// that looks like an embedded literal secret is reduced to "***" so a credential
// accidentally stored literally is not echoed back. The escape "$${" is preserved.
func MaskSecretRefs(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if strings.HasPrefix(s[i:], "$${") {
			b.WriteString("$${")
			i += 3
			continue
		}
		if strings.HasPrefix(s[i:], "${") {
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				// Unterminated reference: pass through (load would already reject it).
				b.WriteString(s[i:])
				break
			}
			b.WriteString(s[i : i+end+1]) // keep "${…}" verbatim
			i += end + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	masked := b.String()
	// Mask a literal API key embedded directly in a URL path/query (no ${…}).
	return maskLiteralSegments(masked)
}

// maskLiteralSegments replaces a long opaque token that looks like an embedded
// literal credential with "***". It is intentionally conservative: it masks a
// path/query segment of >=24 chars that is mostly entropy (alnum, '-', '_') and
// is NOT itself a ${…} reference. Host names and short path words are untouched.
func maskLiteralSegments(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	// Split off the scheme+host, then scan path/query segments.
	schemeEnd := strings.Index(s, "://") + 3
	hostEnd := schemeEnd + strings.IndexAny(s[schemeEnd:], "/?#")
	if hostEnd < schemeEnd {
		return s // no path/query
	}
	head := s[:hostEnd]
	tail := s[hostEnd:]
	// Walk tail splitting on separators, masking opaque high-entropy segments.
	var out strings.Builder
	seg := strings.Builder{}
	flush := func() {
		token := seg.String()
		if looksLikeLiteralSecret(token) {
			out.WriteString("***")
		} else {
			out.WriteString(token)
		}
		seg.Reset()
	}
	for i := 0; i < len(tail); i++ {
		c := tail[i]
		if c == '/' || c == '?' || c == '&' || c == '=' || c == '#' {
			flush()
			out.WriteByte(c)
			continue
		}
		seg.WriteByte(c)
	}
	flush()
	return head + out.String()
}

// looksLikeLiteralSecret reports whether a single URL segment is a long, opaque,
// high-entropy token (a likely API key) rather than a human-readable path word. It
// never flags a ${…} reference (those are masked-kept by MaskSecretRefs already).
func looksLikeLiteralSecret(seg string) bool {
	if strings.Contains(seg, "${") {
		return false
	}
	if len(seg) < 24 {
		return false
	}
	digits, letters, hasUpper := 0, 0, false
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z':
			letters++
		case c >= 'A' && c <= 'Z':
			letters++
			hasUpper = true
		case c == '-' || c == '_':
		default:
			return false // a non-token char means it is not a single opaque secret
		}
	}
	// A real key mixes digits and letters; a long lowercase word (rare) with no
	// digits is left alone to avoid masking legitimate path names.
	return digits > 0 && letters > 0 && (hasUpper || digits >= 4)
}

// detectLiteralSecret is the §7.5 add-time heuristic: it returns human-readable
// locations where a URL or header value appears to embed a LITERAL secret rather
// than a ${env:}/${file:} reference, so `rpc add` can warn (or hard-fail under
// --strict-secrets). A value already using a reference is never flagged.
func detectLiteralSecret(url string, headers map[string]string) []string {
	var hits []string
	if urlHasLiteralSecret(url) {
		hits = append(hits, "the URL")
	}
	// Iterate headers in a deterministic order.
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := headers[k]
		if headerHasLiteralSecret(k, v) {
			hits = append(hits, "header "+k)
		}
	}
	return hits
}

// urlHasLiteralSecret reports a likely literal credential embedded in a URL that
// uses no ${…} reference at all.
func urlHasLiteralSecret(url string) bool {
	if strings.Contains(url, "${") {
		return false // uses a reference somewhere — operator opted in
	}
	if !strings.Contains(url, "://") {
		return false
	}
	schemeEnd := strings.Index(url, "://") + 3
	rel := url[schemeEnd:]
	hostEnd := strings.IndexAny(rel, "/?#")
	if hostEnd < 0 {
		return false
	}
	for _, seg := range strings.FieldsFunc(rel[hostEnd:], func(r rune) bool {
		return r == '/' || r == '?' || r == '&' || r == '=' || r == '#'
	}) {
		if looksLikeLiteralSecret(seg) {
			return true
		}
	}
	return false
}

// headerHasLiteralSecret reports an auth header carrying a literal token (no
// reference). It targets the common auth headers; a non-auth header with a literal
// value is not flagged (too noisy).
func headerHasLiteralSecret(name, value string) bool {
	if strings.Contains(value, "${") {
		return false
	}
	lower := strings.ToLower(name)
	isAuth := lower == "authorization" || strings.Contains(lower, "api-key") ||
		strings.Contains(lower, "token") || strings.Contains(lower, "secret")
	if !isAuth {
		return false
	}
	// Strip a leading scheme word like "Bearer " and inspect the token.
	v := strings.TrimSpace(value)
	if i := strings.IndexByte(v, ' '); i >= 0 {
		v = strings.TrimSpace(v[i+1:])
	}
	return looksLikeLiteralSecret(v) || len(v) >= 12 // any non-empty opaque auth token is suspect
}
