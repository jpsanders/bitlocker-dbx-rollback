---
name: bitlocker-dbx-rollback
description: Recover a Windows PC whose BitLocker drive asks for the recovery key because "Secure Boot policy has unexpectedly changed", by rebuilding the firmware dbx the TPM was sealed against with the dbx-rollback CLI. Use when someone has no BitLocker recovery key after a Linux stick, fwupd or a firmware update changed the Secure Boot revocation list.
---

# bitlocker-dbx-rollback

The TPM unseals a TPM only BitLocker key when PCR 7 (Secure Boot variables and the boot authority) and PCR 11 match
the sealed values. When dbx grew from outside Windows, the sealed dbx is a prefix of today's. This tool finds it,
finds the Microsoft signed updates that rebuild it, and writes a guarded script that restores it.

## Rules for the agent

1. **Ask first:** do they have the 48 digit recovery key? If yes, they should type it; stop.
2. **Mask the stick's updater before anything else:** `sudo systemctl mask --now secureboot-db.service` on every
   Linux stick that will boot the locked PC.
3. **Never** suggest Clear TPM or a firmware "restore security settings" option.
4. Run `dbx-rollback analyze` and continue only on exactly one MATCH. No match means more than dbx changed.
5. Run `plan` until it prints REBUILDS EXACTLY. Missing lists come from Windows updates: `fetch --windows`, or
   `fetch --catalog KB...`, `cabextract`, `psf` and `apply-delta` (msdelta.dll from a Windows install the user owns).
6. Build the kit with `kit`. It refuses sequences that do not rebuild the target.
7. Before the user clears Secure Boot keys, say plainly that this is the one step that can end the no key route if
   the firmware then cannot load its factory keys. Firmware steps one per restart.
8. After `rebuild.sh`, read `rebuild.log`. Windows only after `rebuild.sh verify` prints VERIFIED.
9. Once Windows is up: `manage-bde -protectors -get C:`, and the key goes somewhere safe off the machine.
10. Keep recovery keys, key IDs, serials and dumps out of anything shared.

`dbx-rollback guide` prints the full manual.
