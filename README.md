# nodeagent (POC)

> Hardened compute node. NixOS, LUKS, TPM sealing, WireGuard-only surface. No login. No trust assumptions.

Proof-of-concept demonstrations of `nodeagent`, the cryptographic backbone for licensed software appliances. Each subfolder is a **self-contained, independently buildable Go project** demonstrating one slice of the design in isolation.

## Phases

### [`phase-1-licence-module/`](phase-1-licence-module/) — Signed licences

Ed25519-signed, time-bound licence files. The vendor signs; the device verifies. Tampering, expiry, and wrong-key forgery are all caught locally — no network calls, no central licence server.

| Mode | Verbs |
|---|---|
| `--mode=control` (vendor) | `keygen`, `issue` |
| `--mode=agent` (device) | `verify` |

### [`phase-2-tpm-sealing/`](phase-2-tpm-sealing/) — TPM sealing

Bind arbitrary bytes to a specific TPM 2.0 chip via envelope encryption (AES-256-GCM under a TPM-sealed key). Sealed blobs are unsealable only on the same physical TPM — copy a blob to another machine and it is useless. Closes the "copy the licence file off one paid device onto a second machine" attack.

| Mode | Verbs |
|---|---|
| `--mode=agent` (device) | `seal`, `unseal` |

## Layout

```
.
├── phase-1-licence-module/   standalone Go project — licence module
│   ├── cmd/nodeagent/            keygen, issue, verify
│   ├── internal/licence/         signed-licence library
│   └── docs/phase-1.md
├── phase-2-tpm-sealing/      standalone Go project — TPM seal/unseal
│   ├── cmd/nodeagent/            seal, unseal
│   ├── internal/tpm/             TPM seal/unseal library + envelope encryption
│   └── docs/phase-2.md
└── README.md
```

Each phase folder builds independently — `cd phase-1-licence-module && make test build`, or `cd phase-2-tpm-sealing && make test build`. The folders share no Go code. Later phases conceptually assume the prior phase's deliverable but are demonstrated in isolation here for clarity.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Patent grant included.
