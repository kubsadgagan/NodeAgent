package tpm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// Unseal reverses Seal: it splits the envelope, asks the TPM to release
// the AES key, then AES-GCM decrypts the payload.
//
// The decryption only succeeds when:
//
//   - The blob's framing is intact (both encodeBlob layers parse).
//   - The TPM can re-derive the same SRK that originally sealed the
//     AES key — which only happens on the same physical TPM (or the
//     same swtpm instance with its persisted state directory intact).
//   - The AES ciphertext hasn't been tampered with (GCM auth tag).
//
// Any of those failures returns ErrUnsealFailed; the wrapped error
// names the specific failure mode for diagnostics.
func Unseal(sealed []byte) ([]byte, error) {
	// 1. Split the outer envelope into (sealedKey, nonce‖ciphertext).
	sealedKey, nonceCT, err := decodeBlob(sealed)
	if err != nil {
		return nil, fmt.Errorf("Unseal: outer envelope: %w", err)
	}

	// 2. Split the inner sealed-key blob into TPM (pub, priv).
	pub, priv, err := decodeBlob(sealedKey)
	if err != nil {
		return nil, fmt.Errorf("Unseal: inner sealed key: %w", err)
	}

	// 3. Open TPM, re-derive SRK, Load+Unseal the AES key.
	rwc, err := tpm2.OpenTPM(DefaultDevice)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrTPMUnavailable, DefaultDevice, err)
	}
	defer rwc.Close()

	srkHandle, _, err := tpm2.CreatePrimary(
		rwc,
		tpm2.HandleOwner,
		tpm2.PCRSelection{},
		"",
		"",
		srkTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: CreatePrimary: %v", ErrUnsealFailed, err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	// Load reconstitutes the sealed object as a transient handle.
	// TPM_RC_INTEGRITY here almost always means the blob was produced
	// by a different TPM (or, less commonly, a drifted srkTemplate).
	objHandle, _, err := tpm2.Load(rwc, srkHandle, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("%w: tpm2.Load (likely wrong TPM): %v", ErrUnsealFailed, err)
	}
	defer tpm2.FlushContext(rwc, objHandle)

	aesKey, err := tpm2.Unseal(rwc, objHandle, "")
	if err != nil {
		return nil, fmt.Errorf("%w: tpm2.Unseal: %v", ErrUnsealFailed, err)
	}

	// 4. AES-GCM decrypt the payload.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("%w: aes.NewCipher: %v", ErrUnsealFailed, err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: cipher.NewGCM: %v", ErrUnsealFailed, err)
	}
	nonceSize := aesgcm.NonceSize()
	if len(nonceCT) < nonceSize {
		return nil, fmt.Errorf("%w: payload too short to contain a nonce", ErrBlobMalformed)
	}
	nonce := nonceCT[:nonceSize]
	ciphertext := nonceCT[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// GCM authentication failure: either the AES key was wrong
		// (shouldn't happen — same TPM = same key) or somebody flipped
		// bits in the on-disk blob.
		return nil, fmt.Errorf("%w: AES-GCM Open (likely tampered ciphertext): %v", ErrUnsealFailed, err)
	}
	return plaintext, nil
}
