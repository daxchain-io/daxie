package tools

import (
	"reflect"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// schema.go is the §6.2 schema-inference seam. The MCP tool schemas are INFERRED from
// the SAME domain request/result structs the CLI binds — there are NO hand-written
// duplicate schemas, so CLI/MCP cannot drift (a golden test pins the realized surface).
// Inference is done by the SAME engine the SDK uses internally
// (github.com/google/jsonschema-go), here driven explicitly only so we can correct the
// handful of value types whose Go KIND does not match their JSON wire form.
//
// WHY THIS FILE EXISTS (the value-type fix). The SDK's default inference
// (jsonschema.ForType with empty options) types a Go value by its kind: geth's
// common.Address / common.Hash are [N]byte ARRAYS → JSON "array"; domain.Duration is a
// struct → JSON "object"; a []byte slice → JSON "array" of integers. But every one of
// these MARSHALS as a STRING under encoding/json (address/hash as 0x-hex, Duration via
// its MarshalJSON, []byte as base64). The SDK validates a tool's typed In/Out against
// the inferred schema at call time, so with the default mapping EVERY value-returning
// tool (send, tx_status, tx_wait, gas, balance, …) errors on every successful call with
// `validating tool output: … has type "string", want "array"`, and every input carrying
// a Duration/[]byte (wait.timeout, sign message) is rejected. The MCP server is
// non-functional without this correction.
//
// THE FIX (still inference, not hand-written schemas). jsonschema.For accepts
// ForOptions.TypeSchemas — a per-type override applied BEFORE kind-based inference. We
// map exactly the four value types above to {type:"string"}, run the SAME inference over
// the SAME domain structs (struct tags, required/optional, descriptions all preserved),
// and set the result as the tool's explicit InputSchema/OutputSchema. The SDK then
// resolves and validates against THIS schema. This is the design's "schemas inferred from
// the domain structs" contract realized faithfully: the only change versus the SDK's own
// inference is that address/hash/duration/bytes are typed as the strings they actually
// are. The golden test pins every realized schema so this can never silently change.

// valueTypeSchemas overrides the JSON-schema inference for the Daxie/geth value types
// whose Go kind (array/struct) disagrees with their encoding/json wire form (string).
// time.Time / big.Int are already handled by jsonschema-go's built-in map; these four
// are the ones it does not know about. Keyed by reflect.Type so the override applies
// wherever the type appears (top level, a struct field, or a slice/array element).
var valueTypeSchemas = map[reflect.Type]*jsonschema.Schema{
	// common.Address / common.Hash marshal as 0x-hex strings (geth's MarshalText).
	reflect.TypeFor[common.Address](): {Type: "string"},
	reflect.TypeFor[common.Hash]():    {Type: "string"},
	// domain.Duration marshals as a Go duration string ("5m0s") via its MarshalJSON.
	reflect.TypeFor[domain.Duration](): {Type: "string"},
	// []byte marshals as a base64 string under encoding/json (sign/verify Message/Typed).
	reflect.TypeFor[[]byte](): {Type: "string"},
}

// inferSchema returns the JSON schema for T, inferred from T's Go type by the SAME
// engine the MCP SDK uses, with the value-type overrides applied. It is the ONE place
// every tool's In/Out schema is produced, so the correction is uniform and the golden
// test pins a single, consistent surface. A nil schema (only for the 'any'-like empty
// input, which callers do not pass through here) is never produced for the concrete
// domain structs the tools bind.
func inferSchema[T any]() *jsonschema.Schema {
	s, err := jsonschema.For[T](&jsonschema.ForOptions{TypeSchemas: valueTypeSchemas})
	if err != nil {
		// Inference of a fixed, compile-time-known domain struct cannot fail at runtime;
		// a failure here is a programming error (a new tool bound a type the engine
		// rejects) and must surface loudly at server-build time, exactly as a malformed
		// AddTool would. Registration runs once at New(svc); this never reaches a client.
		panic("mcpserver/tools: schema inference for " + reflect.TypeFor[T]().String() + ": " + err.Error())
	}
	return s
}

// withSchemas stamps the inferred input and output schemas onto a tool definition. The
// SDK uses a non-nil InputSchema/OutputSchema verbatim (resolving + validating against
// it) instead of running its own uncorrected inference — so setting these is what routes
// the SDK through OUR value-type-correct schema. Returns the same *mcp.Tool for chaining
// in the AddTool call sites.
func withSchemas[In, Out any](def *mcp.Tool) *mcp.Tool {
	def.InputSchema = inferSchema[In]()
	def.OutputSchema = inferSchema[Out]()
	return def
}
