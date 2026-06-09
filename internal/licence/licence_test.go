package licence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// newTestLicence builds a plausible licence valid for one hour starting now.
// Helpers like this are idiomatic Go testing: keep each test focused on
// what it is actually asserting, push setup into a helper.
func newTestLicence(t *testing.T, now time.Time) Licence {
	t.Helper()

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	return Licence{
		LicenceID:  "11111111-1111-1111-1111-111111111111",
		DeviceID:   "test-device-01",
		CustomerID: "test-customer",
		IssuedAt:   now,
		NotBefore:  now,
		ExpiresAt:  now.Add(1 * time.Hour),
		Version:    SchemaVersion,
		Nonce:      hex.EncodeToString(nonce),
	}
}

// signToBytes is the "happy path" helper: sign a licence and return the
// on-wire JSON envelope that Verify consumes.
func signToBytes(t *testing.T, l Licence, priv ed25519.PrivateKey) []byte {
	t.Helper()
	signed, err := Sign(l, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

// --- Verify: happy path ---------------------------------------------------

func TestVerify_ValidLicence(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now().UTC()
	l := newTestLicence(t, now)
	raw := signToBytes(t, l, priv)

	got, err := Verify(raw, pub, now.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("Verify returned error on valid licence: %v", err)
	}
	if got.LicenceID != l.LicenceID {
		t.Errorf("returned LicenceID mismatch: got %q, want %q",
			got.LicenceID, l.LicenceID)
	}
	if got.CustomerID != l.CustomerID {
		t.Errorf("returned CustomerID mismatch: got %q, want %q",
			got.CustomerID, l.CustomerID)
	}
}

// --- Verify: time window --------------------------------------------------

func TestVerify_Expired(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now().UTC()
	l := newTestLicence(t, now)
	raw := signToBytes(t, l, priv)

	// Move "now" past expiry.
	_, err = Verify(raw, pub, now.Add(2*time.Hour))
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerify_NotYetValid(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now().UTC()
	l := newTestLicence(t, now)
	// Shift NotBefore into the future relative to the "now" we pass in.
	l.NotBefore = now.Add(10 * time.Minute)
	raw := signToBytes(t, l, priv)

	_, err = Verify(raw, pub, now)
	if !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
}

func TestVerify_ExactlyAtExpiry(t *testing.T) {
	// ExpiresAt is exclusive: at the instant of expiry, the licence
	// is already invalid. This test pins that contract so a future
	// refactor cannot silently flip inclusivity.
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now().UTC()
	l := newTestLicence(t, now)
	raw := signToBytes(t, l, priv)

	_, err = Verify(raw, pub, l.ExpiresAt)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired at exact expiry, got %v", err)
	}
}

// --- Verify: tampering and wrong key --------------------------------------

func TestVerify_TamperedPayload(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now().UTC()
	l := newTestLicence(t, now)
	signed, err := Sign(l, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Mutate the payload after signing: extend the expiry by a year.
	// The signature no longer matches the canonicalised payload, so
	// Verify must reject.
	signed.Payload.ExpiresAt = signed.Payload.ExpiresAt.Add(365 * 24 * time.Hour)

	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal tampered envelope: %v", err)
	}

	_, err = Verify(raw, pub, now)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("expected ErrTampered after payload mutation, got %v", err)
	}
}

func TestVerify_WrongPublicKey(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen signer: %v", err)
	}
	attackerPub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen attacker: %v", err)
	}

	now := time.Now().UTC()
	l := newTestLicence(t, now)
	raw := signToBytes(t, l, priv)

	// Valid licence, signed by one key, verified against a different
	// key. Must fail with ErrTampered — from the verifier's point of
	// view, a wrong-key signature is indistinguishable from a bit
	// flip.
	_, err = Verify(raw, attackerPub, now)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("expected ErrTampered with wrong public key, got %v", err)
	}
}

// --- Verify: malformed and unsupported versions ---------------------------

func TestVerify_MalformedJSON(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	_, err = Verify([]byte("{this is not json"), pub, time.Now())
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed on garbage input, got %v", err)
	}
}

func TestVerify_MalformedSignature(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now().UTC()
	l := newTestLicence(t, now)
	signed, err := Sign(l, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed.Signature = "!!! not base64 !!!"

	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	_, err = Verify(raw, pub, now)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("expected ErrMalformed on bad base64 signature, got %v", err)
	}
}

func TestVerify_UnsupportedVersion(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	now := time.Now().UTC()
	l := newTestLicence(t, now)
	l.Version = 999 // not SchemaVersion
	raw := signToBytes(t, l, priv)

	_, err = Verify(raw, pub, now)
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

// --- Determinism sanity ---------------------------------------------------

func TestCanonical_Stable(t *testing.T) {
	// Canonicalisation must be byte-for-byte stable for a given
	// licence. If this test ever fails, someone introduced
	// non-determinism into the signed bytes and every deployed
	// signature would silently stop verifying.
	now := time.Now().UTC()
	l := newTestLicence(t, now)

	a, err := l.Canonical()
	if err != nil {
		t.Fatalf("canonical a: %v", err)
	}
	b, err := l.Canonical()
	if err != nil {
		t.Fatalf("canonical b: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical output not stable:\n  a = %s\n  b = %s", a, b)
	}
}

// --- Key round trip -------------------------------------------------------

func TestKeys_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir() // Go gives us a temp dir that is auto-cleaned.

	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	privPath := filepath.Join(dir, "signing.key")
	pubPath := filepath.Join(dir, "signing.pub")

	if err := SavePrivateKey(privPath, priv); err != nil {
		t.Fatalf("save private: %v", err)
	}
	if err := SavePublicKey(pubPath, pub); err != nil {
		t.Fatalf("save public: %v", err)
	}

	loadedPriv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("load private: %v", err)
	}
	loadedPub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("load public: %v", err)
	}

	// Sign with the loaded private, verify with the loaded public.
	// If the round trip corrupted anything, this fails.
	now := time.Now().UTC()
	l := newTestLicence(t, now)
	raw := signToBytes(t, l, loadedPriv)

	if _, err := Verify(raw, loadedPub, now); err != nil {
		t.Fatalf("round-trip verify failed: %v", err)
	}
}

// --- Canary against accidental base64 padding drift -----------------------

func TestSignature_IsValidBase64(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().UTC()
	l := newTestLicence(t, now)
	signed, err := Sign(l, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(signed.Signature); err != nil {
		t.Fatalf("Signature is not valid base64: %v", err)
	}
}
