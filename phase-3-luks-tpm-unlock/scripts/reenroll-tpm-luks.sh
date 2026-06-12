#!/usr/bin/env bash
#
# reenroll-tpm-luks.sh — wipe and re-enroll the TPM2-bound LUKS slot
# after a legitimate PCR-affecting change (kernel update, firmware
# update, secure-boot policy change).
#
# Usage:
#   sudo ./reenroll-tpm-luks.sh /dev/vda2 [pcr_policy]
#
#   pcr_policy defaults to "7" (UEFI Secure Boot state only). Other
#   reasonable values: "7", "0+2+4+7" (stricter, breaks on every kernel
#   build), "7+11" (adds boot-attribute measurements).
#
# Requires: cryptsetup, systemd-cryptenroll (both in NixOS by default
# once security.tpm2.enable and boot.initrd.systemd.enable are set).
#
# Recovery: the LUKS passphrase slot is NEVER touched by this script.
# If the script fails halfway through, the passphrase still works for
# the next boot.

set -euo pipefail

DEVICE="${1:-/dev/vda2}"
PCR_POLICY="${2:-7}"

if [[ $EUID -ne 0 ]]; then
    echo "must be run as root (try: sudo $0 $*)" >&2
    exit 1
fi

if [[ ! -b "$DEVICE" ]]; then
    echo "not a block device: $DEVICE" >&2
    exit 1
fi

echo "=== Pre-check: current LUKS slots and tokens ==="
cryptsetup luksDump "$DEVICE" | grep -A2 -E 'Tokens|Keyslots:' || true
echo

echo "=== Wiping existing TPM2 slot (if any) ==="
systemd-cryptenroll --wipe-slot=tpm2 "$DEVICE" || true
echo

echo "=== Enrolling fresh TPM2 slot with PCR policy: $PCR_POLICY ==="
echo "(you'll be prompted for the current LUKS passphrase)"
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="$PCR_POLICY" "$DEVICE"
echo

echo "=== Post-check: new LUKS slots and tokens ==="
cryptsetup luksDump "$DEVICE" | grep -A2 -E 'Tokens|Keyslots:' || true
echo

echo "*** Re-enrollment complete. Reboot to test silent unlock. ***"
