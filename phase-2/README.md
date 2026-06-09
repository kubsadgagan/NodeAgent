# nodeagent — Phase 2 (TPM Sealing)

> Seal arbitrary bytes against the local TPM 2.0 chip. Sealed blobs are unsealable only on the same physical TPM — copy the blob to a different device and it is useless.

Phase 2 of the nodeagent POC, in isolation. This folder is a self-contained Go project demonstrating the hardware-binding property: take any bytes, wrap them in a TPM-bound envelope, prove that only this TPM can recover the original.

## Quick start

Prerequisites: Go 1.25+, plus a Linux device with TPM 2.0 exposed at `/dev/tpmrm0` for the sealing demo. (Encoding tests run on any host.)

```bash
make test         # encoding tests (pure Go) — pass on any host
make build        # binary for the host platform
make build-linux  # cross-compile for the appliance target (static ELF, no CGO)
```

### Demo

```bash
# Seal arbitrary bytes (any data — text, JSON, keys, etc.)
echo "anything you want bound to this TPM" > input.txt
./bin/nodeagent --mode=agent seal --in input.txt --out sealed.bin

# Unseal — only works on the same physical TPM
./bin/nodeagent --mode=agent unseal --in sealed.bin --out recovered.txt
diff input.txt recovered.txt   # byte-identical
```

Move `sealed.bin` to a different machine and `unseal` will fail with `tpm2.Load (likely wrong TPM)`. That refusal is the appliance security property.

Exit codes are part of the public contract: `0` success, `1` usage/IO error, `2` TPM seal/unseal failure.

Detailed write-up: [`docs/phase-2.md`](docs/phase-2.md) — covers swtpm setup on a KVM host, full NixOS install with LUKS, and an end-to-end reboot-survival test.

## How it works (one paragraph)

The TPM has a hard limit on how much it can directly encrypt (about 256 bytes). Real payloads (licences, keys) routinely exceed that. So we use **envelope encryption**: generate a fresh 32-byte AES-256 key, encrypt the plaintext with AES-256-GCM, and ask the TPM to seal just the AES key. On unseal: TPM releases the AES key, AES-GCM decrypts the payload. The plaintext is decryptable only by this TPM (which alone can release the AES key); the AEAD tag detects any tampering with the ciphertext.

## Repository layout

```
.
├── cmd/nodeagent/      single-binary CLI: seal + unseal verbs only
├── internal/tpm/       Seal/Unseal library + tests
├── docs/phase-2.md     full reproduction guide and architecture write-up
├── Makefile            test / build / build-linux / vet / lint / clean
└── go.mod
```

## Tech

Go 1.25, pure Go (no CGO — static cross-compile via `make build-linux`). AES-256-GCM (Go stdlib `crypto/cipher`). TPM 2.0 via `github.com/google/go-tpm` (`legacy/tpm2` package). The convenience helper `tpm2.Seal` in v0.9.5 has a known bug (omits `FlagUserWithAuth`); we bypass it with `CreateKeyWithSensitive` and a hand-rolled template. Only external runtime dependency: `github.com/google/go-tpm`.

## License

Licensed under the [Apache License, Version 2.0](../LICENSE).
