package tpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// Seal encrypts plaintext of arbitrary size against the local TPM 2.0
// chip and returns an opaque blob that can only be decrypted by the
// same TPM.
//
// Why envelope encryption (and not "just call TPM2_Seal on the
// plaintext"):
//
// TPM2_Seal can only handle up to MAX_SYM_DATA bytes per call (typically
// 128–256 depending on the implementation; swtpm caps at 256). Real
// payloads — licences, configs, keys — routinely exceed that. So we use
// the standard envelope-encryption pattern:
//
//  1. Generate a fresh 32-byte AES key in software (crypto/rand).
//  2. Encrypt the plaintext with AES-256-GCM under that key. GCM is an
//     authenticated cipher: any byte-flip in the ciphertext is detected
//     at decrypt time, so an attacker who can read or modify the
//     on-disk blob still can't usefully tamper with it.
//  3. Ask the TPM to seal just the 32-byte AES key. Well under the
//     limit; same per-TPM binding property we wanted from the start.
//  4. Bundle (sealedKey, nonce ‖ ciphertext) into the returned blob
//     using the two-segment encodeBlob framing.
//
// Cost: two random reads, one AES-GCM encrypt, one TPM round-trip.
// Negligible for our payload sizes.
//
// Security properties (each provided by a distinct piece of the stack):
//
//   - Confidentiality of plaintext: AES-256-GCM under a fresh key.
//   - Authenticity of ciphertext:   GCM authentication tag.
//   - Binding to this physical TPM: the AES key is sealed; only the
//     same TPM's storage hierarchy can release it.
//   - No PCR binding yet:           Phase 3 adds that when LUKS auto-
//     unlock lands. Sealed blobs still survive kernel upgrades.
func Seal(plaintext []byte) ([]byte, error) {
	// 1. Fresh AES-256 key.
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("%w: generate AES key: %v", ErrSealFailed, err)
	}

	// 2. AES-GCM encrypt the plaintext.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: aes.NewCipher: %v", ErrSealFailed, err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: cipher.NewGCM: %v", ErrSealFailed, err)
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("%w: generate nonce: %v", ErrSealFailed, err)
	}
	// GCM Seal appends a 16-byte auth tag; output = ciphertext ‖ tag.
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	nonceCT := make([]byte, 0, len(nonce)+len(ciphertext))
	nonceCT = append(nonceCT, nonce...)
	nonceCT = append(nonceCT, ciphertext...)

	// 3. TPM-seal the AES key.
	rwc, err := tpm2.OpenTPM(DefaultDevice)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrTPMUnavailable, DefaultDevice, err)
	}
	defer rwc.Close()

	srkHandle, _, err := tpm2.CreatePrimary(
		rwc,
		tpm2.HandleOwner,
		tpm2.PCRSelection{},
		"", // parent auth (owner hierarchy has no password)
		"", // sensitive auth for the SRK itself
		srkTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: CreatePrimary: %v", ErrSealFailed, err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	// NOTE: do not use tpm2.Seal — its v0.9.5 implementation omits
	// FlagUserWithAuth, producing objects that can never be unsealed.
	// CreateKeyWithSensitive lets us pass our own pinned template
	// (sealedDataTemplate) which has the right attributes.
	priv, pub, _, _, _, err := tpm2.CreateKeyWithSensitive(
		rwc,
		srkHandle,
		tpm2.PCRSelection{}, // no creation-time PCR binding (Phase 3)
		"",                  // parent (SRK) auth
		"",                  // sealed-object auth (empty — we bind to TPM, not password)
		sealedDataTemplate,
		aesKey,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: CreateKeyWithSensitive: %v", ErrSealFailed, err)
	}

	// 4. Bundle: outer envelope = (encodeBlob(pub,priv), nonce ‖ ct).
	//    The inner encodeBlob is the TPM's pub/priv pair; the outer
	//    encodeBlob is our envelope (sealed-key, payload).
	sealedKey, err := encodeBlob(pub, priv)
	if err != nil {
		return nil, fmt.Errorf("%w: encodeBlob (inner sealed key): %v", ErrSealFailed, err)
	}
	envelope, err := encodeBlob(sealedKey, nonceCT)
	if err != nil {
		return nil, fmt.Errorf("%w: encodeBlob (outer envelope): %v", ErrSealFailed, err)
	}
	return envelope, nil
}
