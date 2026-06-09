# Phase 1 — The Licence Module

> One of nine phases in the nodeagent build plan. Phase 1 is the math
> foundation for everything that comes after. No hardware, no network,
> no NixOS — just a small Go library and a CLI that prove the licensing
> idea works on its own.

---

## 1. Phase 1 in plain business terms

> **Phase 1 builds our licensing engine — the cryptographic backbone
> that turns SpaiderSpace from one-off software into a defensible,
> subscription-grade product.**

### 1.1 The problem it solves

Once our software ships to a customer's premises, three risks
materialise immediately:

1. **Revenue leakage.** Without an enforcement mechanism, customers
   can keep using the software indefinitely without ever renewing
   their subscription.
2. **Piracy and replication.** A single paid copy can be cloned to
   any number of machines at zero marginal cost to the customer.
3. **No enforcement leverage.** If a contract is breached or a
   payment lapses, we have no way to make the software stop.

Every software business eventually faces these. Without solving
them, every contract is a one-time sale dressed up as a subscription.

### 1.2 What Phase 1 delivers

A tamper-evident, time-bound digital contract that ships embedded in
every device. Each contract specifies:

- Who the customer is.
- Which device it is bound to.
- When it was issued and when it expires.

The contract carries a digital signature that **only we can produce**
and that **the device can verify on its own** — without ever needing
to contact our servers. If the customer edits a single character, the
signature breaks and the device rejects it. If the contract expires,
the device refuses to keep operating until we issue a renewal.

This is the same class of cryptographic technology that cloud vendors
use to sign software updates and that banks use to authenticate
financial messages. The novelty is using it to bind our software to a
commercial agreement.

### 1.3 Business outcomes this unlocks

- **Recurring revenue model.** Every device must be re-licensed
  periodically. The product moves from one-time sales to renewable
  subscriptions.
- **Per-device, per-customer enforcement.** Each contract is unique
  to one customer and one device. Replication stops being free.
- **Zero per-device operational cost.** No phone-home infrastructure,
  no per-seat licensing servers, no cloud bill that grows with fleet
  size.
- **Addressable in regulated and air-gapped markets.** Verification
  works fully offline. Defence, government, finance, and industrial
  control customers — previously inaccessible — come into scope.
- **No external licensing vendor.** Comparable commercial systems
  (Sentinel LDK, FlexLM, CodeMeter) carry significant annual fees and
  vendor lock-in. We own this end-to-end with no external dependency.

### 1.4 Risks eliminated

| Risk before Phase 1 | Status after Phase 1 |
|---|---|
| Customer keeps using software after subscription ends | Removed — device refuses to operate. |
| Customer forges or edits the licence file | Removed — cryptographic signature breaks. |
| A third party issues fake "vendor" licences | Removed — only our private key produces valid signatures. |
| Licence verification depends on our servers being available | Removed — verification is fully offline. |

### 1.5 Where this sits in the build plan

Phase 1 is the first of nine deliverables. It is the legal and
cryptographic foundation of the appliance.

- **Phases 2–4** physically bind the licence to specific hardware, so
  a customer cannot copy a valid licence onto a second machine.
- **Phases 5–7** add a secure remote channel so we can issue, renew,
  and revoke licences across the deployed fleet from a single control
  plane.
- **Phases 8–9** lock the device down so the only path in is through
  that channel — eliminating the option of bypassing licensing
  entirely.

Phase 1 alone protects against the most common commercial risks
(forgery, expiry evasion, server-dependency). Phases 2–9 compound on
top to make the device tamper-resistant at the hardware level as
well.

### 1.6 Status

**Delivered.** Phase 1 is implemented, tested, and validated
end-to-end. Every claim above is backed by automated tests and a
reproducible demonstration. Engineering detail follows in
Sections 2–5 for readers who want it; non-technical readers can stop
here.

---

## 2. Logical flow

### 2.1 Three actions in the system

```
                  +-----------------+
                  |    VENDOR       |   (you, on your Mac)
                  |   (control)     |
                  +-----------------+
                          |
                          | (1) keygen
                          v
                  +-----------------+
                  | vendor.key      |  <-- secret, never leaves your Mac
                  | vendor.pub      |  <-- public, ships with every device
                  +-----------------+
                          |
                          | (2) issue
                          v
                  +-----------------+
                  |  test.lic       |  <-- signed certificate for one device
                  +-----------------+
                          |
                          | (transport: USB / network / etc.)
                          v
                  +-----------------+
                  |    DEVICE       |   (eventually the NixOS appliance)
                  |    (agent)      |
                  +-----------------+
                          |
                          | (3) verify
                          v
                  Accept (exit 0)  OR  Reject (exit 2 + reason)
```

### 2.2 The "issue" pipeline (vendor side)

```
  human inputs                stdlib + licence pkg                output file
  ------------                -------------------                 -----------

  --device   dev-01    -+
  --customer test       +-->  build Licence struct
  --ttl      30s        |     (UUID, nonce, timestamps,
                        |      schema version)
                        |
                        v
                    +-----------+
                    | Canonical |   sort keys, fix timestamp format,
                    |   ()      |   marshal to deterministic JSON bytes
                    +-----------+
                          |
                          v
                    +-----------+
                    | ed25519   |   priv key + canonical bytes
                    |  .Sign    |   --> 64-byte signature
                    +-----------+
                          |
                          v
                  envelope = { payload, base64(signature) }
                          |
                          v
                    +-----------+
                    | json      |
                    | .Marshal  |
                    +-----------+
                          |
                          v
                       test.lic   (file mode 0644)
```

### 2.3 The "verify" decision tree (device side)

The order matters — each check is a security gate. Earlier checks reject
malformed or unauthenticated input before later checks even look at it.

```
  raw bytes of test.lic
         |
         v
  +-------------------+
  | 1. parse JSON     |--- fail --> reject: "licence malformed"        (exit 2)
  +-------------------+
         | ok
         v
  +-------------------+
  | 2. schema version |--- !=1  --> reject: "licence schema version    (exit 2)
  |    == 1?          |             unsupported"
  +-------------------+
         | ok
         v
  +-------------------+
  | 3. base64 decode  |--- fail --> reject: "licence malformed"        (exit 2)
  |    signature      |
  +-------------------+
         | ok
         v
  +-------------------+
  | 4. canonicalise   |
  |    payload again  |
  +-------------------+
         |
         v
  +-------------------+
  | 5. ed25519.Verify |--- fail --> reject: "licence tampered or       (exit 2)
  |    (pub, bytes,   |             wrong key"
  |     sig)          |
  +-------------------+
         | ok  (everything in payload is now trusted)
         v
  +-------------------+
  | 6. now >=         |--- yes  --> reject: "licence not yet valid"    (exit 2)
  |    not_before?    |
  +-------------------+
         | ok
         v
  +-------------------+
  | 7. now <          |--- no   --> reject: "licence expired"          (exit 2)
  |    expires_at?    |
  +-------------------+
         | ok
         v
  accept: print decoded payload to stdout                              (exit 0)
```

Why this order is security-relevant: nothing inside `payload` is trusted
until step 5 passes. An attacker could put any expiry date they like in
the JSON; we never read those fields until we have proven the bytes were
signed by the real vendor.

---

## 3. Tech used

| Concern | Choice | Why |
|---|---|---|
| Language | **Go 1.25** | One binary, no runtime, easy cross-compile to the NixOS device. |
| Signature scheme | **Ed25519** (stdlib `crypto/ed25519`) | Modern, fast, fixed-size 32-byte keys / 64-byte signatures. Defaults are safe. |
| Random source | `crypto/rand` | OS-level CSPRNG for keys and nonces. |
| Wire format | **JSON** | Human-readable for debugging; ubiquitous tooling. |
| Key on-disk format | **PEM** with custom block types (`NODEAGENT ED25519 PRIVATE KEY`, `... PUBLIC KEY`) | Text-only; safe to `cat`; clear what each file is. |
| File permissions | Private key `0600`, public key / licence `0644` | Private key must be unreadable to other users. |
| Unique identifier | **UUID v4** via `github.com/google/uuid` | One added dependency. Used for `licence_id`. |
| CLI argument parsing | stdlib `flag` package only | No `cobra`/`viper`. Keeps the binary small for the appliance. |
| Test framework | stdlib `testing` | No third-party assertion library. |
| Build | `Makefile` (`make test`, `make build`, `make vet`, `make lint`) | Trivial reproducibility. |
| Static analysis | `go vet` always; `golangci-lint` (errcheck, govet, ineffassign, staticcheck, unused) optional | Tier 1 is free; Tier 2 is heavier. |

**Single external runtime dependency:** `github.com/google/uuid`. Everything
else is the Go standard library. This is intentional — the smaller the
dependency surface, the smaller the supply-chain attack window.

---

## 4. Files in Phase 1

### 4.1 Core licence library — `internal/licence/`

| File | Purpose |
|---|---|
| [licence.go](../internal/licence/licence.go) | The `Licence` and `SignedLicence` types. `SchemaVersion` constant. `Canonical()` method that produces deterministic JSON bytes for signing. |
| [sign.go](../internal/licence/sign.go) | `Sign(Licence, ed25519.PrivateKey) SignedLicence`. Canonicalises the licence, signs the bytes, returns the envelope. |
| [verify.go](../internal/licence/verify.go) | `Verify(raw []byte, ed25519.PublicKey, now time.Time) (Licence, error)`. The seven-step decision tree from §2.3. |
| [keys.go](../internal/licence/keys.go) | `GenerateKeyPair`, `SavePrivateKey`/`SavePublicKey` (PEM), `LoadPrivateKey`/`LoadPublicKey`. |
| [errors.go](../internal/licence/errors.go) | Sentinel errors: `ErrExpired`, `ErrNotYetValid`, `ErrTampered`, `ErrMalformed`, `ErrUnsupportedVersion`. |
| [licence_test.go](../internal/licence/licence_test.go) | Unit tests — see §5.1. |

### 4.2 CLI — `cmd/nodeagent/`

| File | Purpose |
|---|---|
| [main.go](../cmd/nodeagent/main.go) | The single binary. Dispatches on `--mode=agent|control`, then on the positional verb (`keygen`, `issue`, `verify`). Pure shell over `internal/licence`. |

### 4.3 Project meta

| File | Purpose |
|---|---|
| [go.mod](../go.mod) | Module `nodeagent`, Go 1.25.4. |
| [go.sum](../go.sum) | Locked dependency hashes (`github.com/google/uuid` only). |
| [Makefile](../Makefile) | `test`, `build`, `vet`, `lint`, `clean`. |
| [.gitignore](../.gitignore) | Excludes `bin/`, `*.key`, `*.pub`, `*.lic`. Never commit signing material. |
| [.golangci.yml](../.golangci.yml) | Linter config: `errcheck`, `govet`, `ineffassign`, `staticcheck`, `unused`. |

---

## 5. How it is tested

Phase 1 has two test layers:

- **Unit tests** in `licence_test.go`, run with `make test`. These exercise
  the library directly, without the CLI.
- **End-to-end CLI scenarios** in §5.2, run by hand. These exercise the
  binary the way a vendor and a device actually would.

### 5.1 Unit tests (12 cases — all passing)

Run with:

```
make test
# expands to:  go test ./... -count=1 -race
```

| # | Test | What it asserts | Why it matters |
|---|---|---|---|
| 1 | `TestVerify_ValidLicence` | A correctly signed, in-window licence verifies and the decoded fields match. | The happy path. If this ever breaks, nothing else can work. |
| 2 | `TestVerify_Expired` | A licence where `now > expires_at` is rejected with `ErrExpired`. | The whole "stops working when they stop paying" premise. |
| 3 | `TestVerify_NotYetValid` | A licence where `now < not_before` is rejected with `ErrNotYetValid`. | Prevents an attacker from pre-issuing licences and activating them later. |
| 4 | `TestVerify_ExactlyAtExpiry` | At the exact `expires_at` instant, the licence is **already** expired (exclusive boundary). | Pins the contract. Without this, a future refactor could silently flip inclusivity. |
| 5 | `TestVerify_TamperedPayload` | Edit `expires_at` after signing — Verify must reject with `ErrTampered`. | Customer cannot extend their expiry by editing the JSON. The central security claim. |
| 6 | `TestVerify_WrongPublicKey` | Sign with key A, verify against key B — `ErrTampered`. | Customer cannot supply their own keys and forge licences. |
| 7 | `TestVerify_MalformedJSON` | Garbage input (`"{this is not json"`) — `ErrMalformed`, no crash. | Verifier survives hostile input. |
| 8 | `TestVerify_MalformedSignature` | Signature field contains non-base64 — `ErrMalformed`. | Same as above, different angle. |
| 9 | `TestVerify_UnsupportedVersion` | `version: 999` — `ErrUnsupportedVersion`, never falls back to lax defaults. | Closes the door on downgrade games. |
| 10 | `TestCanonical_Stable` | `Canonical()` returns identical bytes on repeated calls for the same licence. | If canonicalisation is non-deterministic, every deployed signature silently breaks. |
| 11 | `TestKeys_SaveLoadRoundTrip` | Save keypair to PEM, load it back, sign+verify still works. | PEM encoding does not corrupt key material. |
| 12 | `TestSignature_IsValidBase64` | The signature field of a freshly signed licence is decodable base64. | Canary against accidental base64 padding drift. |

The tests are run with the **race detector** (`-race`) to catch any
concurrent-access bugs early, and with `-count=1` to disable the test
cache so we always see fresh output.

### 5.2 End-to-end CLI scenarios (7 scenarios — all passing)

Run by hand from `/Users/gagankubsad/GKLabs/NodeAgent`:

```
make build
mkdir /tmp/demo && cd /tmp/demo
```

Each scenario lists the command, the expected output, and the expected
exit code.

#### Scenario 1: vendor key generation

```
$ nodeagent --mode=control keygen --priv vendor.key --pub vendor.pub
wrote private key to vendor.key and public key to vendor.pub
$ echo $?
0
$ ls -l vendor.key vendor.pub
-rw-------  vendor.key   <-- private key 0600
-rw-r--r--  vendor.pub   <-- public key  0644
```

**Proves:** new keypair written with correct permissions.

#### Scenario 2: refusal to overwrite the private key

```
$ nodeagent --mode=control keygen --priv vendor.key --pub vendor.pub
refusing to overwrite existing private key at vendor.key
$ echo $?
1
```

**Proves:** rotating signing material is a deliberate act. You can't
silently destroy your old key with a typo.

#### Scenario 3: issue + verify (happy path)

```
$ nodeagent --mode=control issue \
    --priv vendor.key --device dev-01 --customer test \
    --ttl 30s --out test.lic
issued licence <uuid> (device=dev-01 customer=test expires=...) -> test.lic
$ nodeagent --mode=agent verify --pub vendor.pub --licence test.lic
{
  "licence_id": "...",
  "device_id": "dev-01",
  ...
}
$ echo $?
0
```

**Proves:** end-to-end vendor → device flow works on valid input.

#### Scenario 4: rejection after expiry

```
$ nodeagent --mode=control issue --priv vendor.key --device dev-01 \
    --customer test --ttl 3s --out short.lic
$ nodeagent --mode=agent verify --pub vendor.pub --licence short.lic   # exit 0
$ sleep 4
$ nodeagent --mode=agent verify --pub vendor.pub --licence short.lic
licence expired                                                          # stderr
$ echo $?
2
```

**Proves:** the device honours expiry without contacting anyone. Purely
from timestamps and its local clock.

#### Scenario 5: rejection with the wrong public key

```
$ nodeagent --mode=control keygen --priv attacker.key --pub attacker.pub
$ nodeagent --mode=control issue --priv vendor.key --device dev-01 \
    --customer test --ttl 5m --out fresh.lic
$ nodeagent --mode=agent verify --pub attacker.pub --licence fresh.lic
licence tampered or wrong key
$ echo $?
2
```

**Proves:** the customer cannot supply their own public key and have
their own "licences" accepted. The cryptographic binding between
vendor private key and device public key is enforced.

#### Scenario 6: rejection of malformed input

```
$ echo "{this is not json" > bad.lic
$ nodeagent --mode=agent verify --pub vendor.pub --licence bad.lic
licence malformed
$ echo $?
2
```

**Proves:** the verifier degrades cleanly on garbage. No crash, no
ambiguity about whether the licence was accepted.

#### Scenario 7: usage error on missing flags

```
$ nodeagent --mode=control issue --priv vendor.key
control issue: --priv, --device, --customer, --ttl (>0), --out are required
$ echo $?
1
```

**Proves:** the CLI exits with code 1 (usage error) — distinct from
code 2 (verification failure) — so scripts can distinguish operator
mistakes from real security rejections.

### 5.3 Exit code contract

The exit codes are part of Phase 1's public contract. Phase 9's
air-gap demo will script against them.

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | Usage error or I/O error (missing flags, can't read file, etc.). |
| 2 | Verification failed. The licence reached the verifier, was parsed, and was deliberately rejected (expired / tampered / wrong key / etc.). |

---

## 6. What's next

Phase 1 is done. The licence module is a stable contract that later
phases will build on top of. The next pieces:

- **Phase 2 — TPM sealing.** Take the same licence file produced
  above and seal it inside the device's TPM chip, so it can only be
  read back if the device boots into the exact configuration we
  authorised.
- **Phase 3 — TPM-backed LUKS.** The device's disk only unlocks when
  the TPM is happy. Bolts the licence to the hardware.

See the top-level build plan for the full nine phases.
