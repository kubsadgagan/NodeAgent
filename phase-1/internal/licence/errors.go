package licence

import "errors"

// Sentinel errors returned by Verify. Callers use errors.Is to match
// these, which keeps the check robust even if we later wrap them with
// additional context.
//
// We prefer sentinel errors over typed errors here because each failure
// mode is a single fact ("expired", "not yet valid", etc.) with no
// extra data worth carrying. If a failure ever needs structured detail,
// promote it to a typed error then.
var (
	// ErrExpired means the licence's ExpiresAt is in the past.
	ErrExpired = errors.New("licence expired")

	// ErrNotYetValid means the licence's NotBefore is in the future.
	ErrNotYetValid = errors.New("licence not yet valid")

	// ErrTampered means the signature did not verify against the
	// declared public key. The licence bytes have been modified, or
	// the signature does not belong to this public key.
	ErrTampered = errors.New("licence tampered or wrong key")

	// ErrMalformed means the licence could not be parsed — missing
	// fields, invalid JSON, invalid base64 signature, invalid
	// timestamps, etc.
	ErrMalformed = errors.New("licence malformed")

	// ErrUnsupportedVersion means the licence schema version is not
	// one this agent knows how to verify. Always reject rather than
	// guess.
	ErrUnsupportedVersion = errors.New("licence schema version unsupported")
)
