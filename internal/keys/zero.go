package keys

import (
	"crypto/ecdsa"
	"math/big"
	"runtime"
)

// zeroBytes overwrites b with zeros and keeps it alive past the loop so the
// compiler cannot elide the wipe (§3.10). Safe on nil/empty.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// zeroECDSA wipes a *ecdsa.PrivateKey in place (§3.10). geth's zeroing helper is
// unexported, so keys zeroes the key itself immediately after the sign call: it
// zeroes the big.Int word slice backing D (the secret scalar) and clears the
// public-coordinate words for good measure. Safe on nil.
//
// big.Int stores its magnitude in an internal []Word reachable via Bits(); we
// overwrite that slice (it aliases the int's storage), then SetInt64(0) so the
// value is consistently zero, then KeepAlive so the wipe is not optimized away.
//
// SA1019: ecdsa.PrivateKey.D is deprecated for MODIFICATION because it can produce
// invalid keys — but invalidating the key by zeroing its secret scalar is exactly
// the intent here. There is no non-deprecated way to wipe the secret material in
// place; the key is discarded immediately after.
//
//nolint:staticcheck // deliberate security wipe of the deprecated-for-modification D field
func zeroECDSA(k *ecdsa.PrivateKey) {
	if k == nil {
		return
	}
	if k.D != nil {
		zeroBig(k.D)
	}
	if k.X != nil {
		zeroBig(k.X)
	}
	if k.Y != nil {
		zeroBig(k.Y)
	}
	runtime.KeepAlive(k)
}

// zeroBig overwrites the magnitude words backing a big.Int and resets it to 0.
func zeroBig(n *big.Int) {
	w := n.Bits() // aliases the internal storage
	for i := range w {
		w[i] = 0
	}
	n.SetInt64(0)
	runtime.KeepAlive(n)
}
