// Package tpm seals and unseals small blobs against a TPM 2.0 chip.
//
// The whole package exists to make one promise: bytes sealed on a
// machine can only be unsealed on the same TPM. Move the sealed blob to
// any other machine — even an identical VM — and Unseal returns an
// error. That's the property the entire appliance security model rests
// on; nothing else in nodeagent works without it.
//
// Design choices, deliberately constrained:
//
//   - We use the *legacy* go-tpm API at github.com/google/go-tpm/legacy/tpm2.
//     It is stable, mirrors the official tpm2-seal-unseal example, and
//     has no CGO. The newer TPMDirect API is more idiomatic Go but its
//     surface is still churning.
//
//   - We do NOT persist any TPM handle. CreatePrimary in the storage
//     hierarchy deterministically derives the same Storage Root Key
//     (SRK) every call, given an identical template and the unchanged
//     hierarchy seed inside the TPM. Same SRK in → same encryption of
//     the sealed object's "priv" half → same decryption after reboot.
//     This is what makes the seal survive a power cycle without
//     EvictControl, NV indices, or any host-side state to keep clean.
//
//   - We do NOT bind to any PCR policy. A sealed blob in Phase 2 is
//     bound *only* to this physical TPM; it survives kernel upgrades,
//     bootloader changes, etc. Phase 3 will tighten this to PCR 7 (and
//     friends) once we wire LUKS auto-unlock against the same policy.
//
// Stateless functions, not a Device struct: payloads are ~500 bytes,
// every call opens /dev/tpmrm0 and closes it. Keeps the API trivial.
package tpm

import (
	"errors"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// DefaultDevice is the kernel-managed TPM 2.0 character device. Using
// the resource manager (tpmrm0) — not the raw chip (tpm0) — means the
// kernel handles HMAC sessions and concurrent opens for us.
const DefaultDevice = "/dev/tpmrm0"

// srkTemplate is the storage-root-key template, frozen.
//
// Drift here is the #1 way TPM sealing code silently breaks: change one
// bit of this template and CreatePrimary derives a different SRK,
// previously-sealed blobs fail to Load with TPM_RC_INTEGRITY, and you
// will not be able to tell from the error message what went wrong.
// Both Seal and Unseal must reference *this variable* — never inline
// a copy, never mutate it.
//
// Attributes (FlagStorageDefault) — combination required for a storage
// parent:
//
//   - FixedTPM, FixedParent — the key cannot be duplicated to a
//     different TPM or hierarchy.
//   - SensitiveDataOrigin — TPM generates the sensitive data
//     internally.
//   - UserWithAuth — empty parent auth is allowed.
//   - NoDA — exempt from Dictionary Attack lockout (we don't have a
//     password to brute-force).
//   - Restricted, Decrypt — required to use this as a storage parent
//     for Load.
//
// Symmetric: AES-128-CFB is the standard inner-protection cipher used
// by every TPM storage parent example in go-tpm and the TCG spec.
var srkTemplate = tpm2.Public{
	Type:    tpm2.AlgRSA,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM |
		tpm2.FlagFixedParent |
		tpm2.FlagSensitiveDataOrigin |
		tpm2.FlagUserWithAuth |
		tpm2.FlagNoDA |
		tpm2.FlagRestricted |
		tpm2.FlagDecrypt,
	AuthPolicy: nil,
	RSAParameters: &tpm2.RSAParams{
		Symmetric: &tpm2.SymScheme{
			Alg:     tpm2.AlgAES,
			KeyBits: 128,
			Mode:    tpm2.AlgCFB,
		},
		KeyBits: 2048,
	},
}

// sealedDataTemplate is the public template for the data-bearing object
// we create under the SRK. The convenience helper tpm2.Seal in
// go-tpm v0.9.5 silently produces objects with neither FlagUserWithAuth
// nor a policy, which makes them impossible to Unseal afterwards
// (TPM_RC_AUTH_UNAVAILABLE). We bypass that helper and call
// CreateKeyWithSensitive with this hand-rolled template instead.
//
// Required attributes for a data-bearing object that we want to
// unseal with empty password authorization (PWAP):
//
//   - FixedTPM, FixedParent — standard cannot-duplicate flags
//   - UserWithAuth          — allow HMAC/PWAP auth at unseal time.
//                             Without this, the TPM refuses to unseal.
//   - NoDA                  — exempt from Dictionary Attack lockout
//                             (we have no password to brute-force)
//
// Type=KeyedHash + AlgNull scheme means "sealed data" rather than an
// HMAC key — i.e. the TPM stores opaque bytes that come back unchanged
// from Unseal.
var sealedDataTemplate = tpm2.Public{
	Type:    tpm2.AlgKeyedHash,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM |
		tpm2.FlagFixedParent |
		tpm2.FlagUserWithAuth |
		tpm2.FlagNoDA,
	AuthPolicy: nil,
}

// Sentinel errors. Callers should match these with errors.Is rather
// than string comparison, so we can wrap them with extra context
// without breaking the contract.
var (
	// ErrTPMUnavailable means the TPM device could not be opened
	// (missing device node, EBUSY, EACCES, etc.). Almost always a
	// configuration problem rather than a cryptographic one.
	ErrTPMUnavailable = errors.New("tpm device unavailable")

	// ErrSealFailed means the TPM rejected the seal call. Typically
	// the SRK creation or the seal itself failed; check the wrapped
	// error for the TPM_RC_* code.
	ErrSealFailed = errors.New("tpm seal failed")

	// ErrUnsealFailed means the TPM refused to unseal the blob.
	// The most common cause is "blob produced by a different TPM";
	// the next most common is template drift (see srkTemplate).
	ErrUnsealFailed = errors.New("tpm unseal failed")

	// ErrBlobMalformed means the sealed blob's length-prefixed
	// framing is unparseable. Either the file was truncated or it
	// isn't a sealed blob at all.
	ErrBlobMalformed = errors.New("sealed blob malformed")
)
