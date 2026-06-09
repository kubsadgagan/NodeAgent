package tpm

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// --- Pure-Go tests (run anywhere — Mac, CI, the VM) ----------------------

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
				t.Errorf("pub round-trip mismatch: got %x, want %x", gotPub, tc.pub)
			}
			if !bytes.Equal(gotPriv, tc.priv) {
				t.Errorf("priv round-trip mismatch: got %x, want %x", gotPriv, tc.priv)
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

// --- TPM integration test (runs only where /dev/tpmrm0 exists) ----------
//
// The test skips on the Mac and any host without a TPM. On the
// nixos-luks VM (and eventually a real device) it exercises a full
// seal → unseal round-trip against the actual chip.

func TestSealUnseal_RoundTrip_RealTPM(t *testing.T) {
	if _, err := os.Stat(DefaultDevice); err != nil {
		t.Skipf("no TPM device at %s — skipping (this is normal on dev machines)", DefaultDevice)
	}

	// Multiple sizes — small (under TPM's MAX_SYM_DATA, would have worked
	// with raw TPM_Seal), realistic (a signed licence JSON), and large
	// (proves envelope encryption handles sizes the TPM can't directly).
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
			if len(sealed) == 0 {
				t.Fatal("sealed blob is empty")
			}
			// Sealed bytes should look nothing like the plaintext.
			if bytes.Contains(sealed, tc.plaintext) {
				t.Fatal("sealed blob contains plaintext substring — encryption is broken")
			}

			got, err := Unseal(sealed)
			if err != nil {
				t.Fatalf("Unseal: %v", err)
			}
			if !bytes.Equal(got, tc.plaintext) {
				t.Errorf("plaintext mismatch after round-trip (len got=%d want=%d)", len(got), len(tc.plaintext))
			}
		})
	}
}
