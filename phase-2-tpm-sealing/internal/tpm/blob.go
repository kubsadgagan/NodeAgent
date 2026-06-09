package tpm

import (
	"encoding/binary"
	"fmt"
)

// On-disk framing for a sealed object:
//
//	uint16 BE  pubLen
//	bytes      pub      (sealed object's public part)
//	uint16 BE  privLen
//	bytes      priv     (sealed object's encrypted private part)
//
// No magic header, no version byte, no checksum — Phase 2 keeps the
// format trivial. If we ever need versioning (Phase 4/5 may bundle
// metadata), prepend a 4-byte magic + 1-byte version then.
//
// uint16 is plenty: TPM 2.0 caps sealed object sizes well below 65 KiB
// and our payloads are at most a few hundred bytes.

// encodeBlob serialises (pub, priv) into the on-disk framing.
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

// decodeBlob parses the on-disk framing back into (pub, priv).
//
// Returned slices alias the input — callers that need to retain the
// bytes past the lifetime of `b` should copy them.
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
