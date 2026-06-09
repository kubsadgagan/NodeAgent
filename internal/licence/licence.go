// Package licence defines the licence token format used by nodeagent.
//
// A licence is a small JSON document that proves a device is authorised
// to run the software for a bounded time window. Licences are produced
// by the vendor (control mode) and verified by the device (agent mode).
//
// The wire format is:
//
//	{
//	    "payload":   { ... the Licence struct, canonicalised ... },
//	    "signature": "base64-encoded Ed25519 signature over payload bytes"
//	}
//
// Canonicalisation rules (critical — a signature is only valid over
// exactly the bytes that were signed):
//   - JSON object keys are sorted alphabetically.
//   - No insignificant whitespace.
//   - All timestamps are RFC 3339 in UTC.
//
// This file defines only the data types and canonicalisation. Signing
// lives in sign.go, verification in verify.go, key management in keys.go.
package licence

import (
	"encoding/json"
	"fmt"
	"time"
)

// SchemaVersion is the current version of the Licence struct. Bump this
// whenever fields are added or removed so older agents can reject
// unknown licences cleanly instead of silently ignoring new fields.
const SchemaVersion = 1

// Licence is the payload that gets signed. Every field is mandatory.
//
// JSON tags are lowercase_snake_case to match common convention and to
// keep the wire format stable even if we rename Go fields later.
type Licence struct {
	LicenceID  string    `json:"licence_id"`  // UUID, unique per issued licence
	DeviceID   string    `json:"device_id"`   // TPM-derived in Phase 2; any string for now
	CustomerID string    `json:"customer_id"` // Human-readable, e.g. "spaider-prod-01"
	IssuedAt   time.Time `json:"issued_at"`   // When the vendor signed this licence
	NotBefore  time.Time `json:"not_before"`  // Licence is invalid before this instant
	ExpiresAt  time.Time `json:"expires_at"`  // Licence is invalid at or after this instant
	Version    int       `json:"version"`     // Schema version (see SchemaVersion)
	Nonce      string    `json:"nonce"`       // Random bytes, hex-encoded; makes each licence unique
}

// SignedLicence is the full on-wire envelope: payload plus signature.
// This is what gets written to disk, sent over the tunnel, and sealed
// into TPM.
type SignedLicence struct {
	Payload   Licence `json:"payload"`
	Signature string  `json:"signature"` // base64 standard encoding, no padding stripped
}

// Canonical returns the exact bytes that must be signed and verified.
//
// We marshal the Licence with a deterministic key ordering by going
// through map[string]any. Go's encoding/json sorts map keys
// alphabetically, but struct field order is declaration order — which
// is why we cannot just json.Marshal(l) and sign the result. Struct
// field order is fine today but would silently break if someone
// reorders fields later. Going through a map makes the contract
// explicit.
//
// Returns an error only if marshalling fails, which should not happen
// for well-formed time.Time values.
func (l Licence) Canonical() ([]byte, error) {
	// Convert timestamps to RFC 3339 UTC strings so the wire format
	// is independent of the signer's local timezone.
	m := map[string]any{
		"licence_id":  l.LicenceID,
		"device_id":   l.DeviceID,
		"customer_id": l.CustomerID,
		"issued_at":   l.IssuedAt.UTC().Format(time.RFC3339Nano),
		"not_before":  l.NotBefore.UTC().Format(time.RFC3339Nano),
		"expires_at":  l.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"version":     l.Version,
		"nonce":       l.Nonce,
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("canonicalise licence: %w", err)
	}
	return b, nil
}
