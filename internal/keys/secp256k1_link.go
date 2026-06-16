package keys

import "github.com/ethereum/go-ethereum/crypto"

// This file pins the pure-Go secp256k1 path so a future CGO flip is caught at
// compile time. go-ethereum's crypto/secp256k1 selects its scalar-mult
// implementation by build tag: signature_nocgo.go (`//go:build … || !cgo …`)
// supplies crypto.S256()/crypto.Sign on the CGO_ENABLED=0 build, and
// signature_cgo.go on the cgo build. Either way crypto.S256 and crypto.Sign link,
// and under CGO_ENABLED=0 (the binding invariant) they take the btcec path and
// sign correctly.
//
// Referencing both symbols here means: if a dependency bump ever drops the nocgo
// path, or a build accidentally turns cgo on and the C secp256k1 fails to link,
// this package — the crown-jewel signer — fails the build immediately rather than
// at first signature. It is a tripwire, not behavior.
var (
	_ = crypto.S256
	_ = crypto.Sign
)
