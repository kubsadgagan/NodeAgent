# nodeagent — Build Story

A plain-English walkthrough of how nodeagent is built, one phase at a time. Each phase ends with the gap it deliberately leaves open — which is exactly what the next phase exists to close.

---

# Phase-1

**Agenda:** To prove that a licence was genuinely issued by the vendor and hasn't been altered after the fact, we use digital signatures (specifically, Ed25519). The vendor holds a private key that only they can sign with; every device holds a matching public key that can only verify, never sign. A licence is just a small JSON document with a cryptographic signature attached — the signature ties the document to the private key that signed it. Anyone with the public key can confirm "yes, this was signed by the legitimate vendor," but the only way to *create* a new valid licence is to have the private key (which never leaves the vendor's machine).

**POC:** Pure Go on the Mac. No hardware, no network, no servers — just a library and a CLI.

1. We generate a vendor keypair with Ed25519. The result is a paired keypair: `vendor.key` (private, secret, stays only on the vendor's machine forever) and `vendor.pub` (public, freely shareable, eventually baked into every device that ships). The two halves have **different powers** — only the private side can sign, only the public side can verify, and one cannot be derived from the other. That asymmetry is the entire foundation of the licensing model.

2. The vendor issues a signed licence. The `issue` command takes inputs (device id, customer id, validity duration like 8760 hours), builds a Licence JSON containing a UUID `licence_id`, a random hex `nonce`, three RFC 3339 UTC timestamps (`issued_at`, `not_before`, `expires_at`), and a schema version. The bytes are then **canonicalised** — sorted keys, deterministic timestamp format — so that the signer and verifier are guaranteed to hash exactly the same bytes. The canonical bytes are signed with `vendor.key` using Ed25519. The output is wrapped in an envelope `{ payload, signature }` and written to disk as `test.lic`.

3. The device verifies the licence. With only `vendor.pub` baked in and the licence file in hand, the `verify` command runs four checks **in this exact order**: (a) the JSON parses, (b) the schema version matches what this device knows how to handle, (c) the Ed25519 signature is valid against the canonical bytes — this is the *only* step that touches cryptography, and the one that actually uses `vendor.pub`, (d) the current time falls between `not_before` and `expires_at`. Only if all four pass is the licence accepted. There are no network calls, no central server, no licence authority to phone — the device decides yes or no entirely on its own.

4. What's been proved. Nobody but the vendor can fabricate a valid licence (you need the private key, which never ships). Tampering breaks the signature instantly. Expiry happens automatically once the device's clock crosses `expires_at`. Wrong-key forgery (an attacker signs with their own key and tries to pass it off) is detected by the signature check. And the whole verification works **offline** — devices in air-gapped customer environments (defence, finance, industrial control) can verify their own licences without any external dependency.

5. **What's still possible: copying the licence file.** The licence is just a JSON file sitting on disk. Copy `test.lic` from a paid device to a second machine, and that machine's `verify` will succeed exactly the same way — the signature is still valid, the time window is still open. One paid licence, two devices running the software. **Phase 2 closes this gap by making the licence file un-portable — binding it physically to the device's TPM so a copy on any other machine becomes useless noise.**

---

# Phase-2

**Agenda:** To bind the licence to one specific physical device, we use the device's TPM 2.0 chip — a tamper-proof cryptoprocessor permanently soldered to the motherboard. Whatever we ask the TPM to lock can only be unlocked by that exact same chip. The TPM has no extract-the-master-key button; not even root can read its internal secret. We can ask it to lock something, and later ask it to give it back — but never on a different chip.

**POC:** In POC it's done with swtpm.

1. We built the test environment from scratch: **installed NixOS with a LUKS-encrypted root disk**, set up swtpm on the Ubuntu host, attached the vTPM to the NixOS VM via libvirt, and enabled `security.tpm2.enable` inside NixOS so userspace can reach `/dev/tpmrm0`. **LUKS is currently unlocked by a passphrase you type at every boot — it has its own key (slot 0 in the LUKS header) and is completely separate from the TPM at this stage.**

2. The signed licence file is 400 bytes. But the TPM has a hard size limit (~256 bytes on swtpm) — by spec, it physically cannot seal anything larger than that in one shot. So we couldn't just hand the licence to the TPM and say "lock this." It refused with a "structure is the wrong size" error.

3. I take an envelope (AES-256-GCM), put the test.lic licence file in and lock it with the AES Key `K`. Then ask the TPM to seal just the Key `K`. Save both the TPM's locked-up copy of `K` and the AES-encrypted licence (envelope) on disk as `sealed.bin`.

4. Read `sealed.bin` from disk, split into its two pieces (sealed-K and the AES envelope). Hand sealed-K back to the same physical TPM — only that chip can decode it back into the real `K`. Then use `K` to AES-256-GCM-decrypt the envelope. AES-GCM also verifies the tamper-detection tag; if anyone flipped a single bit on disk, the decrypt step refuses. If both decryptions succeed, you're holding the original signed licence bytes again — byte-for-byte identical to what was put in.

5. Power-cycle the entire machine. After it comes back up, run unseal again. The TPM still produces the same `K`, AES-GCM still decrypts, and the bytes still match — because swtpm's storage seed is persisted on disk between VM boots, so the same SRK is re-derived from scratch on the next boot, and from that SRK the same `K` falls back out of sealed-K. That is what "TPM-bound" actually means in practice: not just for one session, but forever (until the chip dies or the seed dir is wiped).

6. **What's still manual: the LUKS passphrase.** Every reboot still requires typing the disk passphrase at the prompt, because LUKS and TPM are not yet connected — LUKS has slot 0 (the passphrase you set during install) and nothing else. The TPM is fully working but isn't reachable until *after* the disk is unlocked. **Phase 3 closes this gap: add a second LUKS key slot bound to the TPM under a PCR policy, so the TPM auto-releases the disk key at boot when the firmware / bootloader / kernel state matches what we authorised. The passphrase becomes a fallback for recovery only; normal boots are silent.**

---

## Phase 1 + Phase 2 in one breath

> The vendor signs a licence with Ed25519 — only the vendor's private key can do that, but every device can check the signature with the matching public key. Then each device, on receipt of its licence, asks its TPM to envelope-seal it: AES encrypts the licence with a random key K; the TPM seals K alone. The on-disk form is now bound to that one physical chip. To run the system, the device unseals (TPM gives back K, AES decrypts the envelope) and verifies the signature in one go — no network, no central server, no portability. **Phase 1 makes the licence un-forgeable; Phase 2 makes it un-portable.** The remaining manual step at boot — the LUKS passphrase — disappears in Phase 3.
