package keys

import gethkeystore "github.com/ethereum/go-ethereum/accounts/keystore"

// KDF parameters for key material at rest (§3.4). The keystore passphrase runs
// through scrypt with geth's StandardScryptN/StandardScryptP so wallet blobs and
// standalone files are geth v3 compatible:
//
//	N = 262144 (2^18), r = 8, p = 1, dkLen = 32, 32-byte random salt per file.
//
// r and dkLen are fixed inside geth's EncryptDataV3 (scryptR=8, scryptDKLen=32);
// keys only chooses N and p. The admin KDF (scrypt N=2^17) is policyseal/M4 — NOT
// built here; only the param table is named in §3.4.
const (
	// stdScryptN is geth's StandardScryptN = 1<<18 (~256 MiB, ~1 s).
	stdScryptN = gethkeystore.StandardScryptN
	// stdScryptP is geth's StandardScryptP = 1.
	stdScryptP = gethkeystore.StandardScryptP
	// lightScryptN is the test escape hatch (scrypt N=4096), honored ONLY when the
	// manifest was created light (§3.4). It is deliberately NOT geth's LightScryptN
	// (1<<12=4096 too) — the value matches by design — but p stays 1 so the on-disk
	// envelope is identical in shape to a production one.
	lightScryptN = 1 << 12
	lightScryptP = 1

	// kdfName is the v3 KDF identifier; "scrypt" is the only KDF keys writes.
	kdfName = "scrypt"
	// scryptR / scryptDKLen mirror geth's fixed v3 params, recorded in the manifest
	// template (the encrypt path uses geth's internal constants, not these).
	scryptR     = 8
	scryptDKLen = 32
)

// scryptParams returns the (N, p) keys passes to EncryptDataV3/EncryptKey for THIS
// store. light is honored only when the manifest was created light (the caller
// gates this); a production keystore can never be silently downgraded (§3.4).
func (s *Store) scryptParams(light bool) (n, p int) {
	if light {
		return lightScryptN, lightScryptP
	}
	return stdScryptN, stdScryptP
}
