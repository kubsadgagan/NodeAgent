# Phase 2 — TPM Sealing

> One of the build-plan deliverables. Phase 2 takes the signed licence
> from Phase 1 and binds it to a specific TPM 2.0 chip, so a copied
> licence file is useless on any other machine.
>
> Reading time: ~15 minutes. Doing time: ~2–4 hours from a clean
> Ubuntu host to `PHASE2_PASS`.

---

## 1. Phase 2 in plain business terms

> **Phase 2 closes the most basic piracy attack against Phase 1:
> copying the licence file from one paid device to a second machine.**

### 1.1 The hole Phase 1 leaves

Phase 1's signed licence is **forgery-proof** — nobody can edit it or
fabricate a new one without breaking the vendor's signature. But it is
**not copy-proof**. A customer could:

1. Plug a USB drive into a paid device.
2. Copy `licence.json` off.
3. Plug the USB into a second machine.
4. Run nodeagent on that second machine; the signature still verifies;
   the software runs.

One sale, two devices. The most obvious form of piracy, structurally
unstopped by Phase 1 alone.

### 1.2 What Phase 2 delivers

Each device's licence is now **married to that device's TPM 2.0 chip**
through a process called *sealing*. The on-disk licence is replaced by
an opaque encrypted blob. To recover the readable licence, the device
has to ask its TPM to decrypt — and **only that exact physical TPM**
can do so. Copying the sealed blob to another machine produces noise;
the new machine's TPM cannot unseal it.

This is enforced by hardware, not by software. The TPM has no extract
operation for its master key; the key has never existed outside the
chip.

### 1.3 Business outcomes this unlocks

- **Per-device licensing actually works.** "One licence, one device" is
  enforced by the hardware itself, not by an honour system.
- **Disk-clone attacks fail.** Imaging the customer's hard drive onto a
  second machine and booting that machine produces a system that
  refuses to operate — the cloned sealed blob doesn't match the new
  machine's TPM.
- **Customer privacy preserved.** The TPM check happens entirely on the
  device. No phone-home, no central licence server. Compatible with
  regulated and air-gapped customer environments.
- **Zero new dependencies in production.** Every motherboard sold in
  the last decade has a TPM 2.0 chip. No special hardware to buy.

### 1.4 Risks eliminated

| Risk before Phase 2 | Status after Phase 2 |
|---|---|
| Customer copies `licence.json` to a second machine and runs two installations on one paid licence | Removed — sealed blob unseals only on the original TPM |
| Customer images the entire disk to a backup and restores it on different hardware | Removed — sealed blob from original TPM is undecryptable on new TPM |
| Customer keeps the device but swaps the motherboard for a recovered/cloned image | Removed — different physical TPM means different storage seed |

### 1.5 Status

**Delivered.** The acceptance test passes: a licence is sealed, the
machine is rebooted, the sealed blob is unsealed, and the byte-for-byte
content matches the original. The whole stack — go-tpm, swtpm,
libvirt's per-domain TPM state, the envelope-encryption pattern, the
hand-rolled sealed-object template — is verified end-to-end.

---

## 2. Logical flow

### 2.1 The big picture (sealing)

```
                Phase 1 licence file (signed JSON)
                            |
                            v
              +----------------------------+
              | nodeagent --mode=agent seal |
              +----------------------------+
                            |
        +-------------------+----------------------+
        |                                          |
        v                                          v
   random AES-256 key                         AES-256-GCM
   (32 bytes, fresh                            encrypts the
   per seal call)                              licence
        |                                          |
        v                                          v
  +-----------+                              ciphertext + tag
  |    TPM    |                              + 12-byte nonce
  | seals key |
  +-----------+
        |
        v
  sealed key blob
  (TPM-protected,
   ~150 bytes)
        |
        +--------+              +--------+
                 |              |
                 v              v
            +-----------------------------+
            | length-prefixed concat      |
            |  (sealed key) || (nonce|ct) |
            +-----------------------------+
                            |
                            v
                  /var/lib/nodeagent/sealed.bin
                  (mode 0600, on the LUKS-encrypted root)
```

### 2.2 The big picture (unsealing)

```
            /var/lib/nodeagent/sealed.bin
                            |
                            v
              +------------------------------+
              | nodeagent --mode=agent unseal |
              +------------------------------+
                            |
                  split length-prefixed
                            |
        +-------------------+----------------------+
        |                                          |
        v                                          v
   sealed key blob                            nonce + ciphertext
        |                                          |
        v                                          |
  +-----------+                                    |
  |    TPM    |  <-- only this physical TPM        |
  | unseals   |      can return the right key      |
  +-----------+                                    |
        |                                          |
        v                                          v
   AES-256 key  ------------+         +------------+
                            |         |
                            v         v
                       +---------------+
                       |  AES-256-GCM   |
                       |  decrypt + tag |
                       |  verify        |
                       +---------------+
                            |
                            v
                Phase 1 licence file (signed JSON)
                            |
                            v
                  ready for Phase 1's verify
```

### 2.3 The boot chain (where the LUKS passphrase fits)

```
   power on
       |
       v
   +---------+
   |  UEFI   |--> reads /boot/EFI/BOOT/BOOTX64.EFI from the ESP
   +---------+
       |
       v
   +---------------+
   | systemd-boot  |--> reads loader/entries/nixos-generation-1.conf
   +---------------+
       |
       v
   linux kernel + initrd
       |
       v
   +---------------------+
   | initrd: cryptsetup  |--> asks for LUKS passphrase  ← Phase 2 manual step
   +---------------------+      (Phase 3 will replace this with TPM auto-unlock)
       |
       v
   root mounted, systemd takes over
       |
       v
   /dev/tpmrm0 exposed by kernel
       |
       v
   user logs in, runs nodeagent agent seal/unseal commands
```

### 2.4 The on-disk envelope format

```
+----+-----------+----+----------+
| L1 |  sealedKey | L2 | nonceCT  |
+----+-----------+----+----------+
 ^      ^         ^     ^
 |      |         |     |
 |      |         |     +-- nonce (12 bytes) || AES-GCM ciphertext
 |      |         |          (ciphertext includes 16-byte auth tag)
 |      |         +-- length of (nonce + ciphertext), uint16 BE
 |      +-- TPM sealed-object blob:
 |              uint16 BE pubLen | pub | uint16 BE privLen | priv
 +-- length of sealedKey, uint16 BE
```

Two nested layers of the same trivial two-segment framing. Outer
envelope carries (sealed key, encrypted payload); inner sealed-key blob
carries the TPM's (pub, priv) pair.

---

## 3. Tech used

| Concern | Choice | Why |
|---|---|---|
| Hardware emulation | **swtpm 0.7.3** (Ubuntu pkg) | TPM 2.0 software emulator. One per VM. Per-domain persistent state. Same protocol as real chips, so production code is unchanged when we ship to real hardware. |
| VM hypervisor | libvirt + KVM | Already on the dev host. `virt-install` handles vTPM attachment, UEFI firmware, and disk/CD layout in one command. |
| Guest OS | **NixOS 25.11** ("Xantusia") | Declarative configuration in `configuration.nix` — reproducible installs from a single text file. |
| Guest firmware | UEFI (OVMF non-secure-boot) | Required for TPM 2.0. `OVMF_VARS_4M.fd` (not `.ms.fd`) so secure boot doesn't block the NixOS installer kernel. |
| Bootloader | systemd-boot | Modern UEFI bootloader; NixOS manages entries declaratively. |
| Encrypted disk | **LUKS2** via `cryptsetup` | Single LUKS container holds the entire root filesystem. Passphrase prompt at boot until Phase 3 automates it. |
| Filesystem | ext4 inside cryptroot | Standard, well-supported. |
| TPM Go library | **`github.com/google/go-tpm@v0.9.5`**, `legacy/tpm2` package | Pure Go (no CGO — clean static cross-compile). |
| **Workaround in the TPM library** | Bypass `tpm2.Seal`, use `tpm2.CreateKeyWithSensitive` with a hand-rolled template | v0.9.5's convenience `Seal` omits `FlagUserWithAuth`, producing objects that cannot be unsealed. |
| Symmetric cipher | **AES-256-GCM** (Go stdlib `crypto/cipher`) | Authenticated encryption: confidentiality + tamper detection in one step. Standard envelope-encryption building block. |
| Sealed-object size limit | Envelope encryption pattern | TPM's `MAX_SYM_DATA` is ~256 bytes (swtpm). Real licences are ~400 bytes. We seal a 32-byte AES key (well under the limit) and AES-encrypt the payload separately. |
| Cross-compilation | `GOOS=linux GOARCH=amd64 CGO_ENABLED=0` | `CGO_ENABLED=0` produces a fully static ELF that runs on minimal NixOS without depending on host libc. |

---

## 4. Files added or changed

### 4.1 New package — `internal/tpm/`

Five files, all on the Mac, all pure Go, no CGO.

#### `internal/tpm/tpm.go`

```go
// Package tpm seals and unseals small blobs against a TPM 2.0 chip.
//
// The whole package exists to make one promise: bytes sealed on a
// machine can only be unsealed on the same TPM. Move the sealed blob to
// any other machine — even an identical VM — and Unseal returns an
// error.
//
// Stateless functions, not a Device struct: payloads are ~500 bytes,
// every call opens /dev/tpmrm0 and closes it. Keeps the API trivial.
package tpm

import (
	"errors"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// DefaultDevice is the kernel-managed TPM 2.0 character device.
const DefaultDevice = "/dev/tpmrm0"

// srkTemplate — the storage-root-key template, frozen.
//
// Drift here is the #1 way TPM sealing code silently breaks: change
// one bit and CreatePrimary derives a different SRK, previously-sealed
// blobs fail to Load with TPM_RC_INTEGRITY. Both Seal and Unseal must
// reference this variable — never inline, never mutate.
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

// sealedDataTemplate is the public template for the data-bearing object.
//
// The convenience helper tpm2.Seal in go-tpm v0.9.5 silently produces
// objects with neither FlagUserWithAuth nor a policy, which makes them
// impossible to Unseal (TPM_RC_AUTH_UNAVAILABLE). We bypass that helper
// and call CreateKeyWithSensitive with this hand-rolled template.
var sealedDataTemplate = tpm2.Public{
	Type:    tpm2.AlgKeyedHash,
	NameAlg: tpm2.AlgSHA256,
	Attributes: tpm2.FlagFixedTPM |
		tpm2.FlagFixedParent |
		tpm2.FlagUserWithAuth |
		tpm2.FlagNoDA,
	AuthPolicy: nil,
}

// Sentinel errors.
var (
	ErrTPMUnavailable = errors.New("tpm device unavailable")
	ErrSealFailed     = errors.New("tpm seal failed")
	ErrUnsealFailed   = errors.New("tpm unseal failed")
	ErrBlobMalformed  = errors.New("sealed blob malformed")
)
```

#### `internal/tpm/blob.go`

```go
package tpm

import (
	"encoding/binary"
	"fmt"
)

// On-disk framing for a sealed object:
//   uint16 BE  pubLen  | bytes  pub
//   uint16 BE  privLen | bytes  priv
//
// Used at two levels:
//   - inner: (TPM pub, TPM priv) → sealed key blob
//   - outer: (sealed key, nonce ‖ ciphertext) → envelope

func encodeBlob(pub, priv []byte) ([]byte, error) {
	if len(pub) > 0xFFFF {
		return nil, fmt.Errorf("encodeBlob: pub too large (%d bytes, max %d)", len(pub), 0xFFFF)
	}
	if len(priv) > 0xFFFF {
		return nil, fmt.Errorf("encodeBlob: priv too large (%d bytes, max %d)", len(priv), 0xFFFF)
	}
	out := make([]byte, 2+len(pub)+2+len(priv))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(pub)))
	copy(out[2:], pub)
	binary.BigEndian.PutUint16(out[2+len(pub):], uint16(len(priv)))
	copy(out[2+len(pub)+2:], priv)
	return out, nil
}

func decodeBlob(b []byte) (pub, priv []byte, err error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("%w: blob shorter than minimum framing (got %d bytes, need >=4)", ErrBlobMalformed, len(b))
	}
	pubLen := int(binary.BigEndian.Uint16(b[0:2]))
	pubStart := 2
	pubEnd := pubStart + pubLen
	if pubEnd+2 > len(b) {
		return nil, nil, fmt.Errorf("%w: declared pubLen=%d exceeds blob (have %d bytes)", ErrBlobMalformed, pubLen, len(b))
	}
	privLen := int(binary.BigEndian.Uint16(b[pubEnd : pubEnd+2]))
	privStart := pubEnd + 2
	privEnd := privStart + privLen
	if privEnd != len(b) {
		return nil, nil, fmt.Errorf("%w: declared sizes (pub=%d, priv=%d) don't account for %d bytes", ErrBlobMalformed, pubLen, privLen, len(b))
	}
	return b[pubStart:pubEnd], b[privStart:privEnd], nil
}
```

#### `internal/tpm/seal.go`

```go
package tpm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// Seal encrypts plaintext of arbitrary size against the local TPM 2.0
// chip. Uses envelope encryption because TPM2_Seal has a MAX_SYM_DATA
// limit (~256 bytes on swtpm).
//
//  1. Generate a fresh 32-byte AES key.
//  2. Encrypt plaintext with AES-256-GCM.
//  3. TPM-seal just the AES key.
//  4. Bundle (sealedKey, nonce ‖ ciphertext).
func Seal(plaintext []byte) ([]byte, error) {
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("%w: generate AES key: %v", ErrSealFailed, err)
	}

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
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	nonceCT := make([]byte, 0, len(nonce)+len(ciphertext))
	nonceCT = append(nonceCT, nonce...)
	nonceCT = append(nonceCT, ciphertext...)

	rwc, err := tpm2.OpenTPM(DefaultDevice)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrTPMUnavailable, DefaultDevice, err)
	}
	defer rwc.Close()

	srkHandle, _, err := tpm2.CreatePrimary(
		rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: CreatePrimary: %v", ErrSealFailed, err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	// NOTE: do not use tpm2.Seal — its v0.9.5 implementation omits
	// FlagUserWithAuth, producing objects that can never be unsealed.
	priv, pub, _, _, _, err := tpm2.CreateKeyWithSensitive(
		rwc, srkHandle, tpm2.PCRSelection{}, "", "", sealedDataTemplate, aesKey,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: CreateKeyWithSensitive: %v", ErrSealFailed, err)
	}

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
```

#### `internal/tpm/unseal.go`

```go
package tpm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

// Unseal reverses Seal. Succeeds only on the same physical TPM that
// produced the sealed blob; any other TPM returns ErrUnsealFailed
// wrapping a TPM2_LOAD integrity error.
func Unseal(sealed []byte) ([]byte, error) {
	sealedKey, nonceCT, err := decodeBlob(sealed)
	if err != nil {
		return nil, fmt.Errorf("Unseal: outer envelope: %w", err)
	}
	pub, priv, err := decodeBlob(sealedKey)
	if err != nil {
		return nil, fmt.Errorf("Unseal: inner sealed key: %w", err)
	}

	rwc, err := tpm2.OpenTPM(DefaultDevice)
	if err != nil {
		return nil, fmt.Errorf("%w: open %s: %v", ErrTPMUnavailable, DefaultDevice, err)
	}
	defer rwc.Close()

	srkHandle, _, err := tpm2.CreatePrimary(
		rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", srkTemplate,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: CreatePrimary: %v", ErrUnsealFailed, err)
	}
	defer tpm2.FlushContext(rwc, srkHandle)

	objHandle, _, err := tpm2.Load(rwc, srkHandle, "", pub, priv)
	if err != nil {
		return nil, fmt.Errorf("%w: tpm2.Load (likely wrong TPM): %v", ErrUnsealFailed, err)
	}
	defer tpm2.FlushContext(rwc, objHandle)

	aesKey, err := tpm2.Unseal(rwc, objHandle, "")
	if err != nil {
		return nil, fmt.Errorf("%w: tpm2.Unseal: %v", ErrUnsealFailed, err)
	}

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
		return nil, fmt.Errorf("%w: AES-GCM Open (likely tampered ciphertext): %v", ErrUnsealFailed, err)
	}
	return plaintext, nil
}
```

#### `internal/tpm/tpm_test.go`

```go
package tpm

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestEncodeDecode_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		pub  []byte
		priv []byte
	}{
		{"empty", nil, nil},
		{"tiny", []byte{0x01}, []byte{0x02, 0x03}},
		{"typical", bytes.Repeat([]byte{0xAB}, 122), bytes.Repeat([]byte{0xCD}, 187)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := encodeBlob(tc.pub, tc.priv)
			if err != nil {
				t.Fatalf("encodeBlob: %v", err)
			}
			gotPub, gotPriv, err := decodeBlob(enc)
			if err != nil {
				t.Fatalf("decodeBlob: %v", err)
			}
			if !bytes.Equal(gotPub, tc.pub) {
				t.Errorf("pub round-trip mismatch")
			}
			if !bytes.Equal(gotPriv, tc.priv) {
				t.Errorf("priv round-trip mismatch")
			}
		})
	}
}

func TestDecodeBlob_Malformed(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"too short", []byte{0x00}},
		{"only pubLen, no body", []byte{0x00, 0x05}},
		{"declared pubLen overruns", []byte{0xFF, 0xFF, 0x00, 0x00, 0x00}},
		{"trailing garbage", []byte{0x00, 0x01, 0xAA, 0x00, 0x00, 0xBB}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := decodeBlob(tc.in)
			if !errors.Is(err, ErrBlobMalformed) {
				t.Errorf("expected ErrBlobMalformed, got %v", err)
			}
		})
	}
}

// Skips when /dev/tpmrm0 absent (Mac, CI). Runs on the VM.
func TestSealUnseal_RoundTrip_RealTPM(t *testing.T) {
	if _, err := os.Stat(DefaultDevice); err != nil {
		t.Skipf("no TPM device at %s — skipping", DefaultDevice)
	}
	cases := []struct {
		name      string
		plaintext []byte
	}{
		{"tiny", []byte(`{"k":"v"}`)},
		{"realistic_licence", bytes.Repeat([]byte("X"), 400)},
		{"large_4kb", bytes.Repeat([]byte("Y"), 4096)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sealed, err := Seal(tc.plaintext)
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			if bytes.Contains(sealed, tc.plaintext) {
				t.Fatal("sealed blob contains plaintext — encryption broken")
			}
			got, err := Unseal(sealed)
			if err != nil {
				t.Fatalf("Unseal: %v", err)
			}
			if !bytes.Equal(got, tc.plaintext) {
				t.Errorf("plaintext mismatch (len got=%d want=%d)", len(got), len(tc.plaintext))
			}
		})
	}
}
```

### 4.2 CLI updates — `cmd/nodeagent/main.go`

Two new verbs added under `--mode=agent`:

```go
// In runAgent():
case "seal":
    return agentSeal(verbArgs)
case "unseal":
    return agentUnseal(verbArgs)

// Handler bodies — full implementations are in cmd/nodeagent/main.go.
// Both follow the same shape: parse flags → read --in → call
// tpm.Seal or tpm.Unseal → write --out → exit 0 on success,
// exitVerifyFailure (2) on TPM error.
```

See [cmd/nodeagent/main.go](../cmd/nodeagent/main.go) for the full
implementations.

### 4.3 Build updates — `Makefile`

```makefile
# Cross-compile for linux/amd64 (the appliance target).
# CGO_ENABLED=0 produces a fully static ELF that runs on minimal NixOS
# without depending on host libc.
build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/nodeagent-linux-amd64 ./cmd/nodeagent
```

### 4.4 Dependency — `go.mod` / `go.sum`

```
require github.com/google/go-tpm v0.9.5
```

Pure Go; no transitive CGO dependencies.

### 4.5 Guest-side artefacts (not in the repo)

Created on the VM during reproduction:

| Path | Mode | Purpose |
|---|---|---|
| `/usr/local/bin/nodeagent` | 0755 | Cross-compiled Linux binary |
| `/etc/nodeagent/licence.json` | 0600 | Plaintext signed licence (input to Seal) |
| `/var/lib/nodeagent/sealed.bin` | 0600 | TPM-sealed envelope blob |
| `/etc/nixos/configuration.nix` | declarative | NixOS system policy (see §5) |

### 4.6 Host-side artefacts (not in the repo)

Created on the Ubuntu KVM host during reproduction:

| Path | Notes |
|---|---|
| libvirt domain XML for `nixos-luks` | Includes the `<tpm model='tpm-crb' version='2.0'/>` block |
| `/var/lib/libvirt/swtpm/<uuid>/` | **swtpm persistent state — irreplaceable.** Deleting this dir bricks every blob ever sealed against this TPM |
| `/var/lib/libvirt/images/nixos-luks.qcow2` | LUKS-encrypted root disk |
| `/var/lib/libvirt/qemu/nvram/nixos-luks_VARS.fd` | OVMF NVRAM (UEFI boot order, secure-boot state) |

---

## 5. Reproduce Phase 2 from a clean Ubuntu host

> Goal: starting from "Ubuntu 24.04 LTS with KVM but no nodeagent
> work," reach `PHASE2_PASS` end-to-end. Every step lists the
> commands, the expected output, and what each piece actually does.

### Prerequisites

- **Ubuntu 24.04 LTS host** with KVM/libvirt set up. CPU must have
  VT-x or AMD-V. Verify with `egrep -c '(vmx|svm)' /proc/cpuinfo` (any
  nonzero result is fine).
- **A Mac** (or any host that can run Go) for cross-compiling the
  binary. Go 1.25+.
- **A NixOS 25.11 minimal ISO** on the Ubuntu host at
  `/var/lib/libvirt/images/nixos-minimal-25.11-x86_64-linux.iso`.
  Download from [nixos.org/download.html](https://nixos.org/download.html).

### Step 1 — Install swtpm on the Ubuntu host

```bash
sudo apt update
sudo apt install -y swtpm swtpm-tools

# Verify
which swtpm
dpkg -s swtpm | grep -i version
```

Expected: `/usr/bin/swtpm` present, version `0.7.x` (Ubuntu 24.04 ships
0.7.3).

**Why:** swtpm is the userspace TPM 2.0 emulator that libvirt spawns
per-VM. We need it before any VM is created with `--tpm`.

### Step 2 — Create the VM with `virt-install`

```bash
sudo virt-install \
  --name nixos-luks \
  --memory 4096 \
  --vcpus 2 \
  --cpu host \
  --boot firmware=efi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no \
  --disk path=/var/lib/libvirt/images/nixos-luks.qcow2,size=30,format=qcow2,bus=virtio,boot.order=2 \
  --disk path=/var/lib/libvirt/images/nixos-minimal-25.11-x86_64-linux.iso,device=cdrom,bus=sata,readonly=on,boot.order=1 \
  --tpm backend.type=emulator,backend.version=2.0,model=tpm-crb \
  --network network=default \
  --graphics spice \
  --osinfo detect=on,require=off \
  --install no_install=yes \
  --noautoconsole
```

Open the VM's console:

```bash
virt-viewer --connect qemu:///system nixos-luks
```

Expected: NixOS 25.11 installer boots; you land at
`[nixos@nixos:~]$`.

**Why each flag matters:**

- `--tpm backend.type=emulator,backend.version=2.0,model=tpm-crb`
  attaches the vTPM at VM creation time. Hierarchy seed generated on
  first boot persists forever in `/var/lib/libvirt/swtpm/<uuid>/`.
- `firmware.feature0.name=secure-boot,...=no` picks the **non-MS** OVMF
  variant. With MS-keys secure boot, the NixOS installer kernel would
  not boot (it isn't Microsoft-signed).
- `boot.order=1` on the CD, `boot.order=2` on the disk ensures the
  installer wins the boot race on first start.
- `--install no_install=yes` tells virt-install to skip its
  install-transient logic (which silently drops the ISO on the
  persistent definition — a documented Ubuntu 24.04 quirk).

### Step 3 — Make SSH copy-paste work (optional but recommended)

Inside the installer (in virt-viewer):

```bash
echo "nixos:nixos" | sudo chpasswd
```

On the Ubuntu host:

```bash
sudo virsh domifaddr nixos-luks                # note the IP, e.g. 192.168.122.59
ssh nixos@192.168.122.59                       # password: nixos
```

If you see `Connection closed by ... port 22`, the installer is still
booting. Wait 10 seconds.

If you see the "host key has changed" warning (only if you previously
had a different VM at the same IP), clear the stale entry:

```bash
ssh-keygen -f ~/.ssh/known_hosts -R '192.168.122.59'
```

From here on, all `[nixos@nixos:~]$` commands are pasted into the SSH
session.

### Step 4 — Partition the disk

```bash
# Sanity check: vda should be 30G with no partitions, sr0 the installer
lsblk

# Create GPT, ESP, and a placeholder for the LUKS container
sudo parted /dev/vda -- mklabel gpt
sudo parted /dev/vda -- mkpart ESP fat32 1MiB 513MiB
sudo parted /dev/vda -- set 1 esp on
sudo parted /dev/vda -- mkpart cryptroot 513MiB 100%

# Format the ESP
sudo mkfs.fat -F32 -n EFI /dev/vda1

# Verify
lsblk -f
```

Expected `lsblk -f`: `vda1` shows `vfat FAT32 EFI`, `vda2` is empty
(about to become LUKS).

**Why:** UEFI requires a FAT32 EFI System Partition for the bootloader.
Everything else lives inside a single LUKS container — simplest
layout, no LVM.

### Step 5 — LUKS format and ext4

```bash
# Format vda2 as LUKS2. Type "YES" (uppercase) to confirm, then a
# passphrase twice. For a dev VM, "redhatvda2" is fine — Phase 2 isn't
# trying to be production-secure.
sudo cryptsetup luksFormat /dev/vda2

# Open it as /dev/mapper/cryptroot
sudo cryptsetup luksOpen /dev/vda2 cryptroot

# Lay ext4 inside the unlocked container
sudo mkfs.ext4 -L nixos /dev/mapper/cryptroot

# Verify the stack
lsblk -f
```

Expected: `vda2` shows `crypto_LUKS 2`; under it, `cryptroot` shows
`ext4`.

### Step 6 — Mount and generate the NixOS config

```bash
sudo mount /dev/mapper/cryptroot /mnt
sudo mkdir -p /mnt/boot
sudo mount /dev/vda1 /mnt/boot
sudo nixos-generate-config --root /mnt

# Verify the generated hardware-configuration.nix sees LUKS
sudo cat /mnt/etc/nixos/hardware-configuration.nix
```

Expected three key lines in `hardware-configuration.nix`:

```nix
fileSystems."/" = { device = "/dev/mapper/cryptroot"; fsType = "ext4"; };
boot.initrd.luks.devices."cryptroot".device = "/dev/disk/by-uuid/<luks-uuid>";
fileSystems."/boot" = { device = "/dev/disk/by-uuid/<esp-uuid>"; fsType = "vfat"; ... };
```

### Step 7 — Write `configuration.nix`

```bash
sudo tee /mnt/etc/nixos/configuration.nix > /dev/null << 'EOF'
{ config, lib, pkgs, ... }:

{
  imports = [ ./hardware-configuration.nix ];

  # --- Bootloader: UEFI + systemd-boot ---
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # --- Networking: hostname + DHCP on the virtio NIC ---
  networking.hostName = "nixos-luks";
  networking.useDHCP = lib.mkDefault true;

  # --- Time zone ---
  time.timeZone = "Asia/Kolkata";

  # --- Operator user. Password set after first boot via passwd. ---
  users.users.gagan = {
    isNormalUser = true;
    description = "Gagan";
    extraGroups = [ "wheel" "tss" ];   # wheel = sudo, tss = TPM access
  };

  # --- SSH: password auth ON for Phase 2; later phases tighten this ---
  services.openssh = {
    enable = true;
    settings.PasswordAuthentication = true;
    settings.PermitRootLogin = "no";
  };

  # --- TPM 2.0: makes /dev/tpmrm0 accessible to the tss group ---
  security.tpm2.enable = true;
  security.tpm2.tssUser = "tss";
  security.tpm2.abrmd.enable = false;   # use kernel resource manager

  # --- Baseline packages ---
  environment.systemPackages = with pkgs; [
    vim git curl htop tpm2-tools
  ];

  system.stateVersion = "25.11";
}
EOF
```

### Step 8 — Install NixOS, set passwords, reboot

```bash
sudo nixos-install --root /mnt
```

This builds the system closure (~5–15 min, downloads packages), copies
it to `/mnt/nix/store`, installs systemd-boot to the ESP, and prompts
for the **root password** (used as a safety net if first boot fails).

```bash
# Set the gagan password BEFORE reboot, via chroot
sudo nixos-enter --root /mnt -- passwd gagan

# Clean unmount and reboot
sudo umount /mnt/boot
sudo umount /mnt
sudo cryptsetup luksClose cryptroot
sudo reboot
```

SSH drops. The VM reboots and stops at the LUKS passphrase prompt in
virt-viewer.

### Step 9 — Detach the CD and unblock first boot from disk

On the Ubuntu host:

```bash
# Wait for the VM to be shut off (LUKS prompt blocks first boot if you
# don't type the passphrase — that's fine for now; we want to eject
# the ISO before next boot)
sudo virsh shutdown nixos-luks    # or wait for it to stop on its own

# Eject the ISO from the SATA CD slot
sudo virsh change-media nixos-luks sda --eject --config

# Confirm the source line is gone
sudo virsh dumpxml nixos-luks | grep -A2 'device=.cdrom.'

# Boot
sudo virsh start nixos-luks
```

Now in virt-viewer: type the LUKS passphrase (`redhatvda2`) at the
prompt. The installed NixOS boots; sshd comes up.

**Why eject the CD:** UEFI was preferring the CD's installer over the
disk because of `boot.order=1` on the CD. With no ISO attached, UEFI
falls through to the disk's `EFI/BOOT/BOOTX64.EFI` — systemd-boot —
and boots NixOS.

### Step 10 — Confirm the installed system + TPM access

From the Ubuntu host:

```bash
sudo virsh domifaddr nixos-luks
ssh-keygen -f ~/.ssh/known_hosts -R '192.168.122.59'    # OS regenerated keys
ssh gagan@192.168.122.59
```

In the VM:

```bash
hostname                                 # should print: nixos-luks
id                                       # should include groups: wheel, tss
ls -l /dev/tpm*                          # /dev/tpm0 (root:root), /dev/tpmrm0 (tss:tss)
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_getrandom 16 --hex
```

Expected: 32 hex characters (16 random bytes) returned by the TPM.
That's the first real round-trip between userspace and the chip.

### Step 11 — On the Mac: add Go-TPM, write the package, cross-compile

```bash
cd ~/path/to/NodeAgent
go get github.com/google/go-tpm@v0.9.5
go mod tidy
```

Create the five files in `internal/tpm/` exactly as shown in §4.1
(tpm.go, blob.go, seal.go, unseal.go, tpm_test.go).

Add the two new agent verbs to `cmd/nodeagent/main.go` (see
§4.2 — full source in [cmd/nodeagent/main.go](../cmd/nodeagent/main.go)).

Add the `build-linux` target to the Makefile (§4.3).

Then:

```bash
make test                                    # encoding tests pass on Mac
make vet
make build                                   # builds the Mac binary
make build-linux                             # builds bin/nodeagent-linux-amd64
file bin/nodeagent-linux-amd64               # ELF 64-bit, statically linked
```

### Step 12 — Issue a licence and ship binary + licence to the VM

```bash
# Vendor keypair (only once — keep vendor.key safe)
./bin/nodeagent --mode=control keygen --priv /tmp/vendor.key --pub /tmp/vendor.pub

# Issue a 1-year licence
./bin/nodeagent --mode=control issue \
    --priv /tmp/vendor.key \
    --device nixos-luks-01 \
    --customer test \
    --ttl 8760h \
    --out /tmp/test.lic

# Ship to VM via ProxyJump through the Ubuntu host
scp -J gagan@<ubuntu-host-ip> \
    bin/nodeagent-linux-amd64 /tmp/test.lic \
    gagan@192.168.122.59:/tmp/
```

### Step 13 — Install on VM and seal the licence

In the VM:

```bash
sudo mkdir -p /usr/local/bin
sudo install -m 0755 /tmp/nodeagent-linux-amd64 /usr/local/bin/nodeagent

sudo mkdir -p /var/lib/nodeagent /etc/nodeagent
sudo chown gagan:users /var/lib/nodeagent /etc/nodeagent
sudo chmod 0700 /var/lib/nodeagent /etc/nodeagent
install -m 0600 /tmp/test.lic /etc/nodeagent/licence.json

# Baseline
sha256sum /etc/nodeagent/licence.json | tee /tmp/before.sha

# Seal
/usr/local/bin/nodeagent --mode=agent seal \
    --in /etc/nodeagent/licence.json \
    --out /var/lib/nodeagent/sealed.bin
```

Expected: `sealed 400-byte plaintext into 640-byte blob at ...`. The
size growth is the envelope: 32-byte AES key wrapped by TPM (~150
bytes) + 12-byte nonce + ciphertext + 16-byte GCM tag.

**Two gotchas this guide already worked through:**

- **`/usr/local/bin` doesn't exist on NixOS by default.** The
  `mkdir -p` above handles it. Also, `/usr/local/bin` is **not in
  `$PATH`** on NixOS, so we always invoke nodeagent by absolute path.
- **`chown gagan:gagan` fails** because NixOS gives normal users
  `gid=100(users)` as their primary group, not a per-user group. Use
  `gagan:users`.

### Step 14 — In-session round-trip + reboot survival

```bash
# Unseal in the same session — proves the round-trip works
/usr/local/bin/nodeagent --mode=agent unseal \
    --in /var/lib/nodeagent/sealed.bin \
    --out /tmp/round1.json

sha256sum /tmp/round1.json    # should match /tmp/before.sha
diff /etc/nodeagent/licence.json /tmp/round1.json && echo "SAME-BOOT_OK"

# Reboot
sudo reboot
```

After reboot: type the LUKS passphrase, SSH back in, and:

```bash
# Post-reboot unseal — THIS is the acceptance test
/usr/local/bin/nodeagent --mode=agent unseal \
    --in /var/lib/nodeagent/sealed.bin \
    --out /tmp/round2.json

sha256sum /tmp/round2.json    # should STILL match /tmp/before.sha
diff /etc/nodeagent/licence.json /tmp/round2.json && echo "*** PHASE2_PASS ***"
```

If `*** PHASE2_PASS ***` prints, **Phase 2 is complete**. The seal
survived a real power cycle. The whole stack — go-tpm v0.9.5's
`legacy/tpm2` package, the swtpm process, libvirt's swtpm state
directory persistence, the pinned `srkTemplate`, the hand-rolled
`sealedDataTemplate`, the envelope-encryption pattern, and the
two-level on-disk framing — has been proven correct end-to-end.

### Step 15 — Optional: prove the cross-machine binding

To viscerally confirm "this licence is bound to this TPM":

1. Copy `/var/lib/nodeagent/sealed.bin` to your Mac.
2. Spin up a second NixOS VM following Steps 2–10 (different domain
   name, e.g. `nixos-luks-2`). This gets a fresh swtpm with a
   different hierarchy seed.
3. SCP `sealed.bin` from your Mac into the new VM.
4. Run `nodeagent --mode=agent unseal --in sealed.bin --out /tmp/x`.
5. Watch it fail with `tpm2.Load (likely wrong TPM)`.

That failure is Phase 2's claim made concrete. It's not optional in
production thinking, but skippable here.

---

## 6. Common reproduction failures and fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| `virt-install` errors `An install method must be specified` | Missing `--install no_install=yes` flag | Add the flag (§5 Step 2) |
| VM boots straight into UEFI shell or "no bootable device" | CD has `boot.order=1` but no ISO attached, OR ISO source missing | Re-eject CD (§5 Step 9); confirm with `virsh dumpxml \| grep -A2 cdrom` |
| `tpm seal failed: ... structure is the wrong size (0x15)` | Plaintext too large for TPM2_Seal (~256 byte limit) | Use envelope encryption (already done in §4.1 seal.go) |
| `tpm unseal failed: ... authValue or authPolicy is not available (0x2F)` | Sealed object lacks `FlagUserWithAuth` (the v0.9.5 `tpm2.Seal` bug) | Use `CreateKeyWithSensitive` with the hand-rolled `sealedDataTemplate` (§4.1 tpm.go) |
| `chown gagan:gagan` errors `invalid group` | NixOS users default to `users` group, not per-user | Use `gagan:users` |
| `/usr/local/bin/nodeagent: No such file or directory` | NixOS doesn't create `/usr/local/bin` | `sudo mkdir -p /usr/local/bin` first |
| `Permission denied (publickey)` from `gagan@<vm-ip>` | gagan password not set during install | Either redo `nixos-enter --root /mnt -- passwd gagan`, or use SPICE console + `passwd` |
| SSH host-key-changed warning | libvirt recycled the IP; old VM's key cached | `ssh-keygen -f ~/.ssh/known_hosts -R '<vm-ip>'`, retry |
| Unseal succeeds but bytes don't match | Encoding bug, or sealed.bin was sealed by an old buggy binary | Re-seal with the current binary |

---

## 7. What this phase deliberately doesn't do

Listed so the next phases have clear scope:

- **No PCR binding.** The seal is bound to the TPM's storage seed only,
  not to PCRs. Kernel/firmware updates do not break the seal. PCR
  binding is added alongside LUKS auto-unlock in the next phase.
- **No automatic operation.** Sealing/unsealing are manual CLI verbs.
  Service-based "unseal on boot, refuse to start if invalid" comes in
  a later phase.
- **No NixOS module for nodeagent.** The binary is installed by hand
  at `/usr/local/bin/nodeagent`. A proper NixOS module declaration is
  out of scope here.
- **No remote management.** Nothing talks to a vendor control plane;
  every operation runs locally.

The Phase 2 surface is intentionally minimal: prove the *binding*
works. Everything that depends on it gets built on top.
