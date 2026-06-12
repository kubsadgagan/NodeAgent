# nodeagent — Phase 3 (TPM-backed LUKS auto-unlock)

> Wire the device's TPM 2.0 chip into the LUKS unlock path so the encrypted root volume opens silently at boot — no human at the console, no passphrase prompt — when the firmware/bootloader/initrd state matches the policy we authorised.

Phase 3 of the nodeagent POC. This folder is **not a Go project** — Phase 3 is a NixOS configuration change plus one TPM enrollment command. The implementation is declarative: a few lines in `configuration.nix` and a single `systemd-cryptenroll` invocation per device.

## What this delivers

| Before Phase 3 | After Phase 3 |
|---|---|
| Disk asks for passphrase at every boot | Disk auto-unlocks via TPM |
| Boot requires a human at the console | Unattended boot (planned reboots, power-loss recovery work) |
| Disk cloned to second machine + passphrase = working clone | Disk cloned to second machine ⇒ TPM refuses, slot 1 useless |

The LUKS passphrase **remains** as a recovery key slot. If the TPM ever refuses (firmware update, bootloader change, swapped motherboard), the boot falls through to the passphrase prompt cleanly — no data loss.

## Quick start

This phase assumes a working Phase 2 system: NixOS 25.11 with a LUKS-encrypted root volume and a TPM 2.0 exposed at `/dev/tpmrm0`. See [`../phase-2-tpm-sealing/`](../phase-2-tpm-sealing/) for that setup.

Three changes get you from "manual passphrase every boot" to "silent TPM auto-unlock":

```bash
# 1. Enable systemd-style initrd (gets TPM driver into the initrd)
#    Edit /etc/nixos/configuration.nix — add:
#      boot.initrd.systemd.enable = true;
sudo nixos-rebuild switch
sudo reboot                                  # boot once on new initrd

# 2. Enroll the TPM as a LUKS unlock method (PCR 7 = UEFI secure boot state)
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/vda2
# (prompts for the current LUKS passphrase, then adds a new key slot)

# 3. Tell the initrd to actually try the TPM at boot
#    Add to /etc/nixos/configuration.nix:
#      boot.initrd.luks.devices.cryptroot.crypttabExtraOpts = [ "tpm2-device=auto" ];
sudo nixos-rebuild switch
sudo reboot                                  # silent boot — no passphrase prompt
```

A full deployable example NixOS config is in [`nixos/configuration.nix`](nixos/configuration.nix). The detailed reproduction guide with all the gotchas and a kernel-update operator runbook is in [`docs/phase-3.md`](docs/phase-3.md).

## How it works (one paragraph)

The TPM has 24 hash-accumulating registers called **PCRs** that track the boot state — firmware, option ROMs, bootloader, secure boot policy. `systemd-cryptenroll` generates a random unlock secret, asks the TPM to seal it under a policy like "release only if PCR 7 currently equals 0xB5710BF5…", and stores the sealed blob as a new LUKS key slot. At boot, `systemd-cryptsetup` in the initrd asks the TPM to unseal that secret. The TPM checks the current PCR 7 value — if it matches the policy, the secret is released, LUKS unlocks, boot continues silently. If anything in the boot chain has changed (firmware patched, secure-boot policy modified, attacker swapped the bootloader), PCR 7 differs, the TPM refuses, and the boot falls through to the passphrase prompt as a recovery path.

## Repository layout

```
.
├── docs/phase-3.md                 detailed write-up + reproduction guide
├── nixos/configuration.nix         deployable example NixOS config
├── scripts/reenroll-tpm-luks.sh    operator helper (re-enroll after PCR-changing updates)
└── README.md
```

## Tech

NixOS 25.11 (`security.tpm2.enable`, `boot.initrd.systemd.enable`, `boot.initrd.luks.devices.<name>.crypttabExtraOpts`). LUKS2 with the `systemd-tpm2` token type. `systemd-cryptenroll` for slot management. PCR 7 policy (UEFI Secure Boot state). TPM 2.0 via `/dev/tpmrm0`. No new external dependencies beyond what Phase 2 already configured.

## License

Licensed under the [Apache License, Version 2.0](../LICENSE).
