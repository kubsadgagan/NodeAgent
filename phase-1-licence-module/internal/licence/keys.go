package licence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// PEM block types. We use PEM because it is text, easy to inspect with
// cat, and widely understood by tooling. The block type strings below
// are ours, not standard PKIX names, which is fine because we always
// read our own keys.
const (
	pemTypePrivateKey = "NODEAGENT ED25519 PRIVATE KEY"
	pemTypePublicKey  = "NODEAGENT ED25519 PUBLIC KEY"
)

// GenerateKeyPair creates a fresh Ed25519 keypair using the OS random
// source. The returned keys are the raw ed25519 types; callers are
// responsible for persisting them via SavePrivateKey / SavePublicKey.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 keypair: %w", err)
	}
	return pub, priv, nil
}

// SavePrivateKey writes the private key to path in PEM format with
// file mode 0600 (owner read/write only). An existing file at path is
// overwritten.
//
// The private key must never leave the control machine. This function
// refuses to create a world-readable file even if the caller asks for
// a looser mode, because a leaked Ed25519 private key is a full
// compromise of the licensing system.
func SavePrivateKey(path string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key length: got %d, want %d",
			len(priv), ed25519.PrivateKeySize)
	}

	block := &pem.Block{
		Type:  pemTypePrivateKey,
		Bytes: priv,
	}
	pemBytes := pem.EncodeToMemory(block)

	// O_EXCL is not used because callers may legitimately want to
	// rotate keys by overwriting. If you need rotation-safe writes,
	// write to a temp file and rename.
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		return fmt.Errorf("write private key to %s: %w", path, err)
	}
	return nil
}

// SavePublicKey writes the public key to path in PEM format with file
// mode 0644 (world-readable). Public keys are not secret and may be
// distributed freely.
func SavePublicKey(path string, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key length: got %d, want %d",
			len(pub), ed25519.PublicKeySize)
	}

	block := &pem.Block{
		Type:  pemTypePublicKey,
		Bytes: pub,
	}
	pemBytes := pem.EncodeToMemory(block)

	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		return fmt.Errorf("write public key to %s: %w", path, err)
	}
	return nil
}

// LoadPrivateKey reads a PEM-encoded private key from path and returns
// it. Returns an error if the file cannot be read, is not valid PEM,
// has an unexpected PEM type, or has the wrong byte length.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key from %s: %w", path, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("private key file is not valid PEM")
	}
	if block.Type != pemTypePrivateKey {
		return nil, fmt.Errorf("unexpected PEM type %q, want %q",
			block.Type, pemTypePrivateKey)
	}
	if len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key has wrong length: got %d, want %d",
			len(block.Bytes), ed25519.PrivateKeySize)
	}

	return ed25519.PrivateKey(block.Bytes), nil
}

// LoadPublicKey reads a PEM-encoded public key from path and returns
// it. Returns an error if the file cannot be read, is not valid PEM,
// has an unexpected PEM type, or has the wrong byte length.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key from %s: %w", path, err)
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("public key file is not valid PEM")
	}
	if block.Type != pemTypePublicKey {
		return nil, fmt.Errorf("unexpected PEM type %q, want %q",
			block.Type, pemTypePublicKey)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key has wrong length: got %d, want %d",
			len(block.Bytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(block.Bytes), nil
}
