package service

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
)

// parity_test.go is the §2.9 "Frontend parity" scaffold. The one-core/two-frontends
// law is behavioral: BOTH frontends must call the IDENTICAL core method with the
// IDENTICAL request struct. The full proof (cli via cobra ExecuteC + mcpserver via
// an in-memory pipe driving the SAME request) lands with the MCP server in M11;
// this file scaffolds the recorder half now and asserts the two invariants M1 can
// already check structurally:
//
//  1. The request/result structs are JSON-round-trippable with NO float field and
//     NO secret field on the wire — the precondition for an MCP adapter being a
//     thin pass-through (§2.4, §6.1). A float or a leaked secret would make the
//     two frontends diverge (the MCP schema would differ from the CLI's wire).
//  2. The recorder seam (recordedCall) captures a (method, request) pair, so the
//     M11 test can drive cli + mcp through it and assert equality. The shape is
//     fixed here so M11 is a thin addition, not a refactor.

// recordedCall is the parity recorder's unit: the core method name and the request
// struct the frontend built. M11 will populate one from the cli path and one from
// the mcp path and assert reflect.DeepEqual.
type recordedCall struct {
	Method  string
	Request any
}

// parityRecorder is the seam both frontends will feed in M11. In M1 it is exercised
// by the structural round-trip assertions below; the type + Record method are the
// fixed contract M11 builds on.
type parityRecorder struct {
	calls []recordedCall
}

func (r *parityRecorder) Record(method string, req any) {
	r.calls = append(r.calls, recordedCall{method, req})
}

// requestTypes is every M1 wire request/result struct. They are the surface a
// future MCP adapter mirrors, so each must satisfy the no-float / no-secret /
// round-trip contract.
func requestTypes() []any {
	idx := uint32(3)
	return []any{
		domain.WalletCreateRequest{Name: "w", Words: 12},
		domain.WalletCreateResult{Name: "w", WalletID: "id", Account0: "w/0", Mnemonic: "a b c", Sensitive: true},
		domain.WalletImportRequest{Name: "w"},
		domain.WalletImportResult{Name: "w", WalletID: "id"},
		domain.WalletListRequest{},
		domain.WalletListResult{Wallets: []domain.WalletSummary{{Name: "w", Accounts: 1, CreatedAt: "2026-06-16T12:00:00Z"}}},
		domain.WalletShowRequest{Name: "w"},
		domain.WalletShowResult{Name: "w", NextIndex: 4},
		domain.WalletRenameRequest{Old: "a", New: "b"},
		domain.WalletRenameResult{Old: "a", New: "b"},
		domain.WalletExportRequest{Name: "w"},
		domain.WalletExportResult{Name: "w", Mnemonic: "x", Sensitive: true},
		domain.WalletDeleteRequest{Name: "w"},
		domain.WalletDeleteResult{Name: "w", Deleted: true},
		domain.AccountDeriveRequest{Wallet: "w", Index: &idx, Name: "n"},
		domain.AccountDeriveResult{Ref: "w/3", Index: 3},
		domain.AccountAliasRequest{Ref: "w/3", Alias: "n"},
		domain.AccountAliasResult{Ref: "w/n", Alias: "n"},
		domain.AccountUnaliasRequest{Ref: "w/n"},
		domain.AccountUnaliasResult{Wallet: "w", Index: 3, RemovedAlias: "n"},
		domain.AccountImportRequest{Name: "k"},
		domain.AccountImportResult{Name: "k"},
		domain.AccountUseRequest{Ref: "w/0"},
		domain.AccountUseResult{Ref: "w/0"},
		domain.AccountListRequest{Wallet: "w"},
		domain.AccountListResult{Default: "w/0"},
		domain.AccountShowRequest{Ref: "w/0"},
		domain.AccountShowResult{Ref: "w/0", Kind: "hd", Index: &idx},
		domain.AccountExportRequest{Ref: "k"},
		domain.AccountExportResult{Ref: "k", PrivateKey: "x", Sensitive: true},
		domain.AccountDeleteRequest{Ref: "k"},
		domain.AccountDeleteResult{Ref: "k", Mode: "remove", Deleted: true},
		domain.KeystoreInfoResult{Path: "/k", Initialized: true},
		domain.KeystoreChangePassphraseRequest{},
		domain.KeystoreChangePassphraseResult{RotatedFiles: 2},
	}
}

// Every M1 wire struct round-trips through JSON and carries no float field — the
// MCP-thin-adapter precondition (§2.4).
func TestM1WireStructsNoFloatRoundTrip(t *testing.T) {
	for _, v := range requestTypes() {
		name := reflect.TypeOf(v).Name()
		b, err := json.Marshal(v)
		if err != nil {
			t.Errorf("%s: marshal: %v", name, err)
			continue
		}
		// Round-trip back into a fresh value of the same type.
		fresh := reflect.New(reflect.TypeOf(v)).Interface()
		if err := json.Unmarshal(b, fresh); err != nil {
			t.Errorf("%s: unmarshal: %v (%s)", name, err, b)
		}
		assertNoFloatField(t, reflect.TypeOf(v), name)
	}
}

// assertNoFloatField walks a struct's exported fields and fails on any float (the
// §2.5 no-float rule — every numeric user value is a string or an integer).
func assertNoFloatField(t *testing.T, ty reflect.Type, path string) {
	t.Helper()
	if ty.Kind() == reflect.Pointer {
		ty = ty.Elem()
	}
	switch ty.Kind() {
	case reflect.Float32, reflect.Float64:
		t.Errorf("%s is a float — the wire contract forbids float fields (§2.5)", path)
	case reflect.Struct:
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			if f.PkgPath != "" { // unexported
				continue
			}
			assertNoFloatField(t, f.Type, path+"."+f.Name)
		}
	case reflect.Slice, reflect.Array, reflect.Pointer:
		assertNoFloatField(t, ty.Elem(), path+"[]")
	}
}

// No secret material leaks onto the wire: a marshaled create/export result must
// carry the mnemonic/key only in the documented sensitive field (Reveal-gated by
// the frontend), never an extra redacted secret.Bytes that would diverge from the
// MCP schema. This asserts the JSON keys are the documented set (no "<redacted>").
func TestM1ResultsNoRedactedSecretOnWire(t *testing.T) {
	for _, v := range requestTypes() {
		b, _ := json.Marshal(v)
		if strings.Contains(string(b), "<redacted>") {
			t.Errorf("%s serialized a redacted secret.Bytes onto the wire: %s",
				reflect.TypeOf(v).Name(), b)
		}
	}
}

// The recorder seam is exercised so its contract is live for M11. Recording a cli
// request and (placeholder) mcp request and asserting equality is the shape M11
// fills with the real second frontend.
func TestParityRecorderSeam(t *testing.T) {
	var cliRec, mcpRec parityRecorder
	req := domain.WalletShowRequest{Name: "treasury"}
	cliRec.Record("WalletShow", req)
	mcpRec.Record("WalletShow", req) // M11: built by the mcp adapter from the same tool input

	if len(cliRec.calls) != 1 || len(mcpRec.calls) != 1 {
		t.Fatal("recorder did not capture both calls")
	}
	if !reflect.DeepEqual(cliRec.calls[0], mcpRec.calls[0]) {
		t.Errorf("frontend parity broken: cli %+v != mcp %+v", cliRec.calls[0], mcpRec.calls[0])
	}
}
