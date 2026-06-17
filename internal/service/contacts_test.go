package service

import (
	"context"
	"testing"

	"github.com/daxchain-io/daxie/internal/domain"
	"github.com/ethereum/go-ethereum/common"
)

// contacts_test.go covers the M3 contacts use cases (add/list/show/remove) and the
// --to contact resolution that SendTx's resolveDest performs.

func TestContacts_AddListShowRemove(t *testing.T) {
	svc, _, _ := sendService(t, someAddr(70))
	ctx := context.Background()
	addr := common.HexToAddress("0x52908400098527886E0F7030069857D2E4169EE7")

	if _, err := svc.ContactAdd(ctx, domain.LocalCLI(),
		domain.ContactAddRequest{Name: "exchange", Address: addr.Hex()}); err != nil {
		t.Fatalf("ContactAdd: %v", err)
	}

	list, err := svc.ContactList(ctx, domain.LocalCLI(), domain.ContactListRequest{})
	if err != nil {
		t.Fatalf("ContactList: %v", err)
	}
	if len(list.Contacts) != 1 || list.Contacts[0].Name != "exchange" {
		t.Fatalf("list = %+v, want one contact 'exchange'", list.Contacts)
	}
	if list.Contacts[0].Address != addr.Hex() {
		t.Errorf("address = %q, want %q", list.Contacts[0].Address, addr.Hex())
	}

	// Show is case-insensitive.
	show, err := svc.ContactShow(ctx, domain.LocalCLI(), domain.ContactShowRequest{Name: "EXCHANGE"})
	if err != nil {
		t.Fatalf("ContactShow (case-insensitive): %v", err)
	}
	if show.Contact.Name != "exchange" {
		t.Errorf("show name = %q, want exchange", show.Contact.Name)
	}

	rem, err := svc.ContactRemove(ctx, domain.LocalCLI(), domain.ContactRemoveRequest{Name: "exchange"})
	if err != nil {
		t.Fatalf("ContactRemove: %v", err)
	}
	if !rem.Removed {
		t.Error("Removed = false, want true")
	}
	if _, err := svc.ContactShow(ctx, domain.LocalCLI(), domain.ContactShowRequest{Name: "exchange"}); err == nil {
		t.Error("show after remove should be ref.not_found")
	}
}

func TestContacts_ShowMissing_Exit10(t *testing.T) {
	svc, _, _ := sendService(t, someAddr(71))
	_, err := svc.ContactShow(context.Background(), domain.LocalCLI(),
		domain.ContactShowRequest{Name: "nope"})
	if err == nil || domain.AsError(err).Exit != domain.ExitNotFound {
		t.Fatalf("expected ref.not_found exit 10, got %v", err)
	}
}

func TestContacts_BadAddress_Exit2(t *testing.T) {
	svc, _, _ := sendService(t, someAddr(72))
	_, err := svc.ContactAdd(context.Background(), domain.LocalCLI(),
		domain.ContactAddRequest{Name: "bad", Address: "not-an-address"})
	if err == nil || domain.AsError(err).Exit != domain.ExitUsage {
		t.Fatalf("expected usage exit 2 for a bad address, got %v", err)
	}
}

// TestSendTx_ResolvesContactName proves --to accepts a contact name: the send
// resolves the name to its address and echoes the name in the result Dest.
func TestSendTx_ResolvesContactName(t *testing.T) {
	from := someAddr(73)
	dest := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	svc, f, _ := sendService(t, from)

	if _, err := svc.ContactAdd(context.Background(), domain.LocalCLI(),
		domain.ContactAddRequest{Name: "cold-wallet", Address: dest.Hex()}); err != nil {
		t.Fatalf("ContactAdd: %v", err)
	}

	f.SendRawFn = func(ctx context.Context, raw []byte) (common.Hash, error) {
		return common.HexToHash("0x0"), nil
	}
	req := domain.TxRequest{From: from.Hex(), To: "cold-wallet", Amount: "1wei"}
	res, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	if err != nil {
		t.Fatalf("SendTx --to contact: %v", err)
	}
	if res.To.Address != dest {
		t.Errorf("resolved to %s, want %s", res.To.Address.Hex(), dest.Hex())
	}
	if res.To.Name != "cold-wallet" {
		t.Errorf("Dest.Name = %q, want cold-wallet (the contact echo)", res.To.Name)
	}
}

func TestSendTx_UnknownRecipient_Exit10(t *testing.T) {
	from := someAddr(74)
	svc, _, _ := sendService(t, from)
	req := domain.TxRequest{From: from.Hex(), To: "no-such-contact", Amount: "1wei"}
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	if err == nil || domain.AsError(err).Exit != domain.ExitNotFound {
		t.Fatalf("expected ref.not_found exit 10 for an unknown --to, got %v", err)
	}
}

// M7 ACTIVATES ENS as a `--to` destination: an UNRESOLVABLE name is now
// ref.not_found (exit 10) — it resolves against the network instead of the M6
// usage.unsupported reject, and never signs to an all-zero address.
func TestSendTx_ENSRecipient_UnresolvedIsRefNotFound(t *testing.T) {
	from := someAddr(75)
	svc, _, _ := sendService(t, from) // bare fake ⇒ the name has no on-chain record
	req := domain.TxRequest{From: from.Hex(), To: "vitalik.eth", Amount: "1wei"}
	_, err := svc.SendTx(context.Background(), domain.LocalCLI(), req, nil)
	assertCode(t, err, domain.CodeRefNotFound)
}
