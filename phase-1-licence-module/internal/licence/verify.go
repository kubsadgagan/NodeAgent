package licence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Verify validates a raw on-wire licence against a vendor public key and
// returns the decoded Licence on success. It returns one of the sentinel
// errors defined in errors.go on failure, wrapped with context using fmt.Errorf.
// Callers should match with errors.Is, not string comparison.
//
// Order of checks (the order is security-relevant):
//  1. Unmarshal the envelope. Malformed input fails fast.
//  2. Reject unknown schema versions. Forward compatibility is opt-in,
//     never automatic.
//  3. Re-canonicalise the payload and verify the signature. No field
//     inside the payload is trusted before this check passes.
//  4. Validate the time window (NotBefore, ExpiresAt) against the
//     provided "now". The caller supplies "now" so tests can exercise
//     all branches without sleeping.
//
// Why take raw []byte instead of a SignedLicence? Because the bytes are
// what we signed, and re-marshalling a SignedLicence struct would go
// through Go's struct JSON encoding, not our canonical map encoding.
// Keeping Verify on []byte makes the contract unambiguous.
func Verify(raw []byte, pub ed25519.PublicKey, now time.Time) (Licence, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Licence{}, fmt.Errorf(
			"invalid public key length: got %d, want %d",
			len(pub), ed25519.PublicKeySize,
		)
	}

	// Step 1: parse the envelope.
	var envelope SignedLicence
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return Licence{}, fmt.Errorf("%w: unmarshal envelope: %v", ErrMalformed, err)
	}

	// Step 2: schema version gate. Reject anything we don't know how
	// to interpret. This closes the door on downgrade games where an
	// attacker crafts a "version 0" licence hoping we fall back to
	// lax defaults.
	if envelope.Payload.Version != SchemaVersion {
		return Licence{}, fmt.Errorf(
			"%w: got version %d, want %d",
			ErrUnsupportedVersion, envelope.Payload.Version, SchemaVersion,
		)
	}

	// Step 3: signature check. Everything inside Payload is untrusted
	// until this line passes.
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil {
		return Licence{}, fmt.Errorf("%w: decode signature: %v", ErrMalformed, err)
	}

	canonical, err := envelope.Payload.Canonical()
	if err != nil {
		return Licence{}, fmt.Errorf("%w: canonicalise for verify: %v", ErrMalformed, err)
	}

	if !ed25519.Verify(pub, canonical, sig) {
		return Licence{}, ErrTampered
	}

	// Step 4: time window. The payload is now trusted.
	if now.Before(envelope.Payload.NotBefore) {
		return Licence{}, ErrNotYetValid
	}
	if !now.Before(envelope.Payload.ExpiresAt) {
		// "!now.Before(expires)" means now >= expires. We choose
		// exclusive expiry: the licence is valid up to but not
		// including ExpiresAt. This matches how HTTP cache expiry
		// and JWT "exp" are conventionally interpreted.
		return Licence{}, ErrExpired
	}

	return envelope.Payload, nil
}
