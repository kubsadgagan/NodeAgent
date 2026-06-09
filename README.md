# nodeagent

> Issue and verify Ed25519-signed software licences, and seal each licence into the device's TPM 2.0 chip so a copied licence file is useless on any other machine. Devices verify and seal entirely offline.

`nodeagent` is a single Go binary with two modes. The vendor runs it in `--mode=control` to generate a signing keypair and issue time-bound, signed licence files. The customer device runs it in `--mode=agent` to:

- **Verify** licences against an embedded vendor public key (tampering, expiry, and wrong-key forgery all caught locally).
- **Seal** a licence against its physical TPM 2.0 chip — replacing the on-disk licence with an opaque encrypted blob that only that exact TPM can decrypt. Copy the blob to any other device and it's just noise.

No network, no central licence server, no phone-home. Every check happens on the device.

## Quick start

Prerequisites: Go 1.25+.

```bash
make test         # run the licence + tpm package tests
make build        # produces ./bin/nodeagent for your host platform
make build-linux  # produces ./bin/nodeagent-linux-amd64 (static ELF for appliances)
```

### Demo 1 — issue a licence and verify it

```bash
# Vendor side — generate a signing keypair (once)
./bin/nodeagent --mode=control keygen \
    --priv vendor.key --pub vendor.pub

# Vendor side — issue a 5-minute licence for one device
./bin/nodeagent --mode=control issue \
    --priv vendor.key --device dev-01 --customer test \
    --ttl 5m --out test.lic

# Device side — verify the licence
./bin/nodeagent --mode=agent verify \
    --pub vendor.pub --licence test.lic
```

Exit codes: `0` success, `1` usage/IO error, `2` verification failure (expired, tampered, wrong key, malformed, unsupported schema version).

### Demo 2 — seal a licence to the local TPM

Requires a Linux device with a TPM 2.0 chip exposed at `/dev/tpmrm0`. (Verify with `ls /dev/tpmrm0`.)

```bash
# Seal — replaces a plaintext licence with a TPM-bound encrypted blob
./bin/nodeagent --mode=agent seal \
    --in test.lic --out test.lic.sealed

# Unseal — only works on the same physical TPM
./bin/nodeagent --mode=agent unseal \
    --in test.lic.sealed --out /tmp/recovered.lic

diff test.lic /tmp/recovered.lic   # byte-identical
```

Move `test.lic.sealed` to a different machine and `unseal` will fail with `tpm2.Load (likely wrong TPM)`. That refusal is the appliance security property.

Detailed write-ups:

- [`docs/phase-1.md`](docs/phase-1.md) — the licence-signing machinery
- [`docs/phase-2.md`](docs/phase-2.md) — TPM sealing, from a clean host to end-to-end test

## Repository layout

```
.
├── cmd/nodeagent/      # single-binary CLI (mode + verb dispatch)
├── internal/licence/   # signed-licence library
├── internal/tpm/       # TPM 2.0 seal/unseal with envelope encryption
├── docs/               # per-phase documentation
├── Makefile            # test / build / build-linux / vet / lint / clean
└── go.mod
```

## Tech

Go 1.25, pure Go (no CGO — static cross-compile to Linux is one `make build-linux` away). Ed25519 signing via `crypto/ed25519`. AES-256-GCM envelope encryption via `crypto/cipher`. TPM 2.0 via `github.com/google/go-tpm` (`legacy/tpm2` package). JSON envelopes on the wire, PEM-encoded keys on disk. Stdlib `flag` for CLI parsing. Only external runtime dependencies: `github.com/google/uuid`, `github.com/google/go-tpm`.

## License

Proprietary — not for redistribution.
