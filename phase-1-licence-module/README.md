# nodeagent

> Issue and verify Ed25519-signed software licences. Devices verify entirely offline — tampering, expiry, and wrong-key forgery all caught locally.

`nodeagent` is a single Go binary with two modes. The vendor runs it in `--mode=control` to generate a signing keypair and issue time-bound, signed licence files. The customer device runs it in `--mode=agent` to verify those licences against an embedded vendor public key. Verification needs no network — the device decides yes or no on its own.

## Quick start

Prerequisites: Go 1.25+.

```bash
make test         # run the licence package tests (12 cases)
make build        # produces ./bin/nodeagent
```

### Demo — issue a licence and verify it

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

Exit codes are part of the public contract: `0` success, `1` usage/IO error, `2` verification failure (expired, tampered, wrong key, malformed, unsupported schema version).

Detailed write-up: [`docs/phase-1.md`](docs/phase-1.md).

## Repository layout

```
.
├── cmd/nodeagent/      # single-binary CLI (mode + verb dispatch)
├── internal/licence/   # signed-licence library
├── docs/               # documentation
├── Makefile            # test / build / vet / lint / clean
└── go.mod
```

## Tech

Go 1.25, pure Go (no CGO). Ed25519 signing via `crypto/ed25519`. JSON envelopes on the wire, PEM-encoded keys on disk. Stdlib `flag` for CLI parsing. Only external runtime dependency: `github.com/google/uuid`.

## License

Licensed under the [Apache License, Version 2.0](../LICENSE).
