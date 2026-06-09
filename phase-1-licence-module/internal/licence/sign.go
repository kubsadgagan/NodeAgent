package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Sign produces a SignedLicence from a Licence and a vendor private key.
//
// The signature is computed over the canonicalised JSON of the payload
// (see Licence.Canonical). The same canonicalisation is repeated on the
// verifier side — if either side changes how bytes are produced, every
// signature breaks. This is intentional and acts as a guardrail against
// accidental schema changes slipping through unnoticed.
//
// Sign does not validate the Licence's semantic content. A caller can
// produce a signed licence that is already expired. That is a feature,
// not a bug: it lets tests exercise the Verify expiry path.
func Sign(l Licence, priv ed25519.PrivateKey) (SignedLicence, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return SignedLicence{}, fmt.Errorf(
			"invalid private key length: got %d, want %d",
			len(priv), ed25519.PrivateKeySize,
		)
	}

	canonical, err := l.Canonical()
	if err != nil {
		return SignedLicence{}, fmt.Errorf("canonicalise for signing: %w", err)
	}

	sig := ed25519.Sign(priv, canonical)

	return SignedLicence{
		Payload:   l,
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}
