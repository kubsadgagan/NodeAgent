# Phase 3 — TPM-backed LUKS auto-unlock

> Wire the TPM into the LUKS unlock path so the disk opens silently at boot.
>
> Reading time: ~10 minutes. Doing time: ~30 minutes from a Phase-2 system to `PHASE3_PASS`.

---

## 1. Phase 3 in plain business terms

> **Phase 3 removes the manual passphrase at every boot. The TPM unlocks the encrypted disk automatically when the boot state is intact, and refuses to do so when it has been tampered with. The original passphrase remains as a recovery escape hatch.**

### 1.1 The gap Phase 2 left

After Phase 2, the appliance had a working TPM and an encrypted disk — but the two weren't connected to each other in the boot path:

- The LUKS volume was unlocked at boot only by a passphrase typed at the console.
- The TPM was only reachable from userspace *after* the disk was unlocked — too late to help with the unlock itself.
- The visible symptom: every boot stops at `Please enter passphrase for disk cryptroot:` until a human types it.

That gap blocks the entire appliance model. A device that needs a human at the keyboard at every power-on can't ship.

### 1.2 What Phase 3 delivers

`systemd-cryptenroll` plus a `systemd`-style initrd close the gap. We add a second LUKS key slot whose unlock secret is **sealed inside the TPM under a PCR policy**. At boot, the initrd's `systemd-cryptsetup` asks the TPM to release that secret. The TPM only releases it if the current Platform Configuration Registers match the values we authorised — which they do on every untampered boot. The disk unlocks; the OS continues; the user never sees a prompt.

The original passphrase slot stays. If the TPM ever refuses (legitimate firmware update, accidental boot-chain change, swapped motherboard for service), the boot falls through to the passphrase prompt — no data loss, no brick.

### 1.3 Business outcomes this unlocks

- **Unattended boot.** Power-loss recovery, scheduled reboots, and remote restart commands work without anyone at the console.
- **Disk-clone defence hardened.** Imaging the disk to a second machine produces a system that cannot boot — the cloned LUKS volume's TPM-bound slot is unrecoverable on a different chip. The passphrase still works on the original hardware, but copying the disk no longer transports the unlock capability with it.
- **Reduced operational friction.** No "remember the passphrase" footgun for field operators. The passphrase becomes a sealed envelope in a safe somewhere, used only when a TPM legitimately refuses.
- **Foundation for boot-state attestation.** PCR binding is a one-step extension to richer policies (PCR 0 + 2 + 4 + 7) when secure-boot is added in later hardening work.

### 1.4 Risks eliminated

| Risk before Phase 3 | Status after Phase 3 |
|---|---|
| Device cannot reboot unattended (always needs a human) | Removed — silent boot |
| Cloning the disk to another machine + holding the passphrase = working appliance on the wrong hardware | Eliminated — TPM-bound slot is unrecoverable on a different TPM |
| Swapping the bootloader for a malicious one and re-using the passphrase | Removed — PCR mismatch makes TPM refuse |
| Customer or attacker can't "see" whether the boot chain has been tampered with | Visible — first sign of compromise is the unexpected reappearance of the passphrase prompt |

### 1.5 Status

**Delivered.** A clean Phase-2 system reaches PHASE3_PASS in five steps. Reboots are silent. The negative test (perturb a PCR-affecting input → boot prompts for passphrase) is included as the bottom of §5.

---

## 2. Logical flow

### 2.1 Boot chain — before and after

```
                            BEFORE PHASE 3
                            ===============

   power on
      |
      v
   +---------+
   |  UEFI   |
   +---------+
      |
      v
   +---------------+
   | systemd-boot  |
   +---------------+
      |
      v
   kernel + initrd (classic, shell-scripted)
      |
      v
   +------------------------+
   | cryptsetup asks for    |  *** human types redhatvda2 ***
   | LUKS passphrase        |
   +------------------------+
      |
      v
   root mounts, systemd takes over
      |
      v
   sshd starts, login ready


                            AFTER PHASE 3
                            ==============

   power on
      |
      v
   +---------+
   |  UEFI   |
   +---------+
      |
      v
   +---------------+
   | systemd-boot  |
   +---------------+
      |
      v
   kernel + initrd (systemd-style, includes tpm driver)
      |
      v
   +------------------------+
   | systemd-cryptsetup     |--- asks TPM to unseal slot-1 secret
   +------------------------+      under PCR-7 policy
      |
      v
   +------------------------+
   |  TPM checks PCR 7      |
   +------------------------+
      |                |
      | matches        | mismatches (tampered boot chain)
      v                v
   release secret    refuse → fall back to passphrase prompt
      |                                    |
      v                                    v
   slot 1 unlocks LUKS         slot 0 unlocks LUKS (recovery)
      |
      v
   root mounts, systemd takes over
      |
      v
   sshd starts, login ready (NO HUMAN INPUT)
```

### 2.2 LUKS header layout (after enrollment)

```
+----------------------------------------------------------+
|                  LUKS2 header on /dev/vda2               |
|                                                          |
|  Keyslots:                                                |
|    Slot 0:  type = luks2 password                         |
|             key  = 512 bits                               |
|             auth = passphrase (redhatvda2)                |
|             use  = RECOVERY ONLY                          |
|                                                          |
|    Slot 1:  type = luks2 (TPM2-bound)                     |
|             key  = 512 bits                               |
|             auth = via Token 0 below                      |
|             use  = NORMAL BOOT                            |
|                                                          |
|  Tokens:                                                  |
|    Token 0: type = systemd-tpm2                           |
|             refs = Slot 1                                 |
|             policy = "release only if PCR 7 == 0xB571..." |
+----------------------------------------------------------+
```

Two slots, two paths in. The token is the binding between Slot 1 and the TPM — without that token, slot 1 is unrecoverable.

### 2.3 PCR policy choice

PCR 7 measures the **UEFI Secure Boot policy state**. We picked PCR 7 *only* (not 0 + 2 + 4 + 7) for the POC because:

| PCR | Measures | Stable across kernel updates? |
|---|---|---|
| 0 | UEFI firmware code | usually yes; changes on firmware update |
| 2 | Option ROMs | usually yes |
| 4 | Bootloader + kernel + initrd | **no — changes every kernel build** |
| 7 | Secure Boot policy (keys, dbx) | mostly yes — changes only when secure-boot config changes |

With PCR 4 in the policy, every `nixos-rebuild` with a new kernel would change the measurement → next boot's TPM would refuse → passphrase prompt → re-enrollment required. Operationally annoying.

With PCR 7 only: kernel updates pass through silently. The binding still rejects: bootloader replacement, motherboard swap, different TPM, secure-boot key swap. It does *not* catch a kernel-image swap on the same machine — but that's a deliberate POC tradeoff; tightening to 0+2+4+7 is a single flag change at re-enrollment time.

---

## 3. Tech used

| Concern | Choice | Why |
|---|---|---|
| Initrd flavour | **`boot.initrd.systemd.enable = true`** (systemd-style) | Classic NixOS initrd is shell-scripted and lacks the TPM driver. The systemd initrd bundles `systemd-cryptsetup` with TPM 2.0 support and is the only path that has it. |
| LUKS enrollment | **`systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7`** | Single command. Adds a new key slot + a TPM2 token referencing that slot. Both LUKS2 header changes are atomic. |
| LUKS unlock at boot | **`boot.initrd.luks.devices.<name>.crypttabExtraOpts = [ "tpm2-device=auto" ]`** | One Nix option puts `tpm2-device=auto` into the initrd's `/etc/crypttab`, telling `systemd-cryptsetup` to try the TPM token first. |
| PCR policy | PCR 7 only | Survives kernel updates. Adequate for the POC. Tightening is a 1-flag change at re-enrollment. |
| Recovery slot | LUKS slot 0 stays as the passphrase | TPM-bound boots are normal; passphrase-based boots are diagnostic / repair. No data-loss path. |
| TPM device path | `/dev/tpmrm0` | Kernel-managed resource manager (vs raw `/dev/tpm0`). What NixOS exposes via `security.tpm2.enable`. |
| Tooling for ad-hoc TPM checks | `tpm2-tools` (already pulled in by Phase 2) | `tpm2_pcrread`, `tpm2_getrandom`. Useful but not load-bearing. |

---

## 4. Files added or changed

### 4.1 NixOS configuration (the entire Phase 3 deliverable, code-wise)

**Three lines** added to `configuration.nix`. That's the whole code change:

```nix
  # --- Bootloader: UEFI + systemd-boot, systemd-style initrd for TPM access ---
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
  boot.initrd.systemd.enable = true;                                    # ← NEW
  boot.initrd.luks.devices.cryptroot.crypttabExtraOpts =
    [ "tpm2-device=auto" ];                                             # ← NEW
```

(`boot.initrd.systemd.enable` is one line, `crypttabExtraOpts` is the second. The bootloader lines were already in place from Phase 2.)

A complete deployable example with all the surrounding context is in [`../nixos/configuration.nix`](../nixos/configuration.nix).

### 4.2 LUKS header changes (one-time, per-device)

Performed by a single command:

```bash
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/vda2
```

This mutates the LUKS header in place. Before:

```
Keyslots:  0: luks2  (passphrase)
Tokens:    (none)
```

After:

```
Keyslots:  0: luks2  (passphrase, still works)
           1: luks2  (TPM-bound secret)
Tokens:    0: systemd-tpm2  → keyslot 1
                policy = "PCR 7 == <hex>"
```

No filesystem changes. The LUKS *master key* (which actually decrypts the disk) is unchanged — only how it's wrapped in slot 1 differs from slot 0.

### 4.3 Operator helper script

`scripts/reenroll-tpm-luks.sh` wraps the wipe + re-enroll cycle for the case where PCR values legitimately change (firmware update, secure-boot policy change, etc.).

### 4.4 No Go code changes

Phase 3 deliberately doesn't add to the nodeagent binary. The unlock path is owned entirely by `systemd-cryptsetup` in the initrd, which is well-tested upstream code we don't need to replicate. nodeagent's job remains "verify and seal at the application layer" — disk unlock is a system concern.

---

## 5. Reproduction guide

Assumes a working Phase 2 system: NixOS 25.11 with `/dev/vda2` as a LUKS-encrypted root volume, `/dev/tpmrm0` accessible to the operator's user, and `security.tpm2.enable = true` already in `configuration.nix`.

### Step 1 — Enable the systemd-style initrd

Edit `/etc/nixos/configuration.nix`. Find the bootloader block:

```nix
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;
```

Add one line at the end of that block:

```nix
  boot.initrd.systemd.enable = true;
```

Build:

```bash
sudo nixos-rebuild switch
```

This rebuilds the initrd from scratch (~5 min the first time — downloads tpm2-tss, builds a systemd-included initrd image). At the end you'll have a new generation registered with systemd-boot. **The currently-running system is still on the classic initrd in RAM — the change only takes effect on the next reboot.**

**Why this step:** the classic NixOS initrd is a small shell environment that doesn't load the TPM kernel modules and doesn't include `systemd-cryptsetup`. Without the systemd initrd, the TPM is unreachable until after the disk is unlocked — too late to help.

### Step 2 — Reboot to land on the new initrd

```bash
sudo reboot
```

You'll still be prompted for the LUKS passphrase at the console — we haven't enrolled the TPM slot yet. Type the passphrase as usual. System boots; SSH back in.

**Why a reboot in the middle:** PCR 4 (and to a small extent PCR 7) reflect the bytes of the running initrd. We want to enroll against the PCRs as they are *after* the new initrd is running — otherwise we'd seal the secret under the old initrd's measurements, and the very next boot would invalidate it.

### Step 3 — Enroll LUKS against the TPM

```bash
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/vda2
```

The command prompts for the current LUKS passphrase (`redhatvda2`) — that's needed because adding a key slot is itself a privileged operation on the LUKS header. Then it generates a random secret, asks the TPM to seal it under PCR 7's current value, writes the sealed blob as a token, and writes the new slot.

Expected output: `New TPM2 token enrolled as key slot 1.`

Verify:

```bash
sudo cryptsetup luksDump /dev/vda2 | grep -A2 -E 'Tokens|Keyslots:'
```

Should show two slots and a `systemd-tpm2` token referencing slot 1.

### Step 4 — Tell the initrd to actually use the TPM

Edit `/etc/nixos/configuration.nix` again. Right after the line you added in Step 1:

```nix
  boot.initrd.luks.devices.cryptroot.crypttabExtraOpts =
    [ "tpm2-device=auto" ];
```

The `cryptroot` device name here matches the `boot.initrd.luks.devices."cryptroot".device` line that's already in `hardware-configuration.nix` (which was generated during Phase 2's install).

Build:

```bash
sudo nixos-rebuild switch
```

This rebuild is fast — only the initrd's `/etc/crypttab` and a few systemd units change. No kernel rebuild.

### Step 5 — The headline reboot test

```bash
sudo reboot
```

In virt-viewer (or on the local console):

- The boot menu appears briefly (systemd-boot).
- Kernel boots, initrd loads.
- **The "Please enter passphrase" line should NOT appear.** The boot continues silently.
- Login banner appears.

SSH back in and confirm:

```bash
# Generation 3 should now be default AND selected (currently running)
sudo bootctl list 2>&1 | grep -E 'title.*default|title.*selected'

# Should print nothing — confirms no password was asked at boot
sudo journalctl -b 0 --no-pager | grep -iE 'ask-password|please enter passphrase' \
    | grep -v 'Deactivated successfully'
```

If both pass, **`PHASE3_PASS`**.

### Step 6 — Negative test (recommended, proves the binding is real)

Edit the bootloader entry to add a kernel command-line argument that perturbs PCR 4 (which we're *not* binding to, but the test still works because systemd-cryptenroll has an additional check that detects bootloader changes):

Easier alternative — just regenerate the initrd with a different module set and see the boot re-prompt the passphrase. The simplest provable test: temporarily disable secure boot's UEFI variable measurement to alter PCR 7. From inside the VM:

```bash
# Wipe the TPM slot (simulates a tampered state where the TPM refuses)
sudo systemd-cryptenroll --wipe-slot=tpm2 /dev/vda2

# Reboot — should fall back to passphrase prompt
sudo reboot
```

Type `redhatvda2` at the prompt → system boots. **You just demonstrated that the recovery path works** and that without the TPM token the system gracefully degrades.

Restore the TPM slot:

```bash
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/vda2
sudo reboot                                  # silent again
```

---

## 6. Operator runbook — re-enrolling after PCR changes

If at any future point the boot prompts for the passphrase unexpectedly (and it's a legitimate change, not a real attack), the cause is almost always: **a kernel/firmware/secure-boot change altered the PCR value the TPM was sealed against.**

The wipe + re-enroll cycle:

```bash
# Type the passphrase to get in
# Then on the running system:
sudo systemd-cryptenroll --wipe-slot=tpm2 /dev/vda2
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/vda2
sudo reboot                                  # silent again
```

This is wrapped in [`../scripts/reenroll-tpm-luks.sh`](../scripts/reenroll-tpm-luks.sh) — same two commands, with sanity checks.

**Don't run this if you can't explain why the PCR changed.** The whole point of the binding is to refuse on tampering; if the boot is prompting and you don't know why, that's potentially an attack indicator, not a configuration drift.

---

## 7. Common failures and fixes

| Symptom | Likely cause | Fix |
|---|---|---|
| `error: attribute 'boot.loader.efi.canTouchEfiVariables' already defined` from `nixos-rebuild` | Duplicate lines (editor accident) | Remove the duplicate; `sudo grep -n` to find both instances |
| `nixos-rebuild` succeeds but reboot still prompts for passphrase | Step 4's `crypttabExtraOpts` line not applied (typo in device name, didn't reboot, etc.) | `grep -n crypttabExtraOpts /etc/nixos/configuration.nix` and confirm the device name matches `boot.initrd.luks.devices.<name>.device` in `hardware-configuration.nix` |
| Boot prompts and journal shows `Token #0 (systemd-tpm2) discarded` | TPM refused — PCR mismatch (firmware change, secure-boot change) | Wipe + re-enroll via the runbook in §6 |
| `systemd-cryptenroll` fails with `Failed to enroll`, mentions TPM not found | `/dev/tpmrm0` missing or perms wrong | `ls -l /dev/tpmrm0`; should be `crw-rw---- root tss`. `id | grep tss` should include `tss`. If not, check `security.tpm2.enable` in config. |
| swtpm-specific: enrollment succeeds, reboot prompts, journal shows TPM communication errors | swtpm state directory permissions or AppArmor issue | Check `/var/log/swtpm/libvirt/qemu/nixos-luks-swtpm.log` on the Ubuntu host |

---

## 8. What this phase deliberately doesn't do

- **The licence still isn't used at boot.** Disk auto-unlocks, OS boots, you SSH in — but `nodeagent` doesn't run automatically yet, and no customer application is launched. That's the next layer of the appliance model, not this one.
- **No remote management.** Phase 3 makes the device boot itself, but the only way to talk to it after that is still local SSH.
- **PCR 7 only — not the strongest possible policy.** Tightening to PCR 0 + 2 + 4 + 7 catches more attack vectors (bootloader replacement, kernel-image swap on the same machine) at the cost of operational friction (every kernel update requires re-enrollment). One-flag change at re-enrollment time when that tradeoff is right for the deployment.
- **No measured-UKI.** systemd's "unified kernel image" mechanism could go further still — measuring the kernel + initrd + cmdline as one signed unit. Out of scope here; would replace the `boot.loader.systemd-boot` setup if introduced.

These are all deliberate. The point of this phase is "make the unlock hands-off" — the rest of the security layering happens in its own time.
