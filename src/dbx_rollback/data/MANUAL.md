# dbx-rollback

Get a BitLocker drive to unlock by itself again after a Secure Boot dbx change, without the recovery key.

## Synopsis

```
dbx-rollback analyze --efivars DIR --dislocker-log FILE [--out FILE]
dbx-rollback fetch --out DIR [--lvfs] [--secureboot-objects] [--windows ROOT] [--catalog KB]
dbx-rollback plan --factory-dbx FILE --target FILE --payloads DIR
dbx-rollback psf --cab FILE --psf FILE --out DIR
dbx-rollback apply-delta --msdelta DLL --python EXE [--base FILE] --delta FILE --out FILE
dbx-rollback kit [--efivars DIR] --factory-dbx FILE --target FILE --sequence FILE... --out DIR
dbx-rollback guide | man [--install] [--raw]
```

## When it applies

The BitLocker recovery screen says **Secure Boot policy has unexpectedly changed**, the drive's protectors are TPM
and Numerical Password sealed to PCRs 7 and 11, and the firmware's dbx gained entries from outside Windows (an Ubuntu
stick's `secureboot-db.service`, `fwupd`, a BIOS update). PK, KEK and db must still equal the firmware's factory
copies, and the firmware must offer a factory key load.

## Commands

**`analyze`**

Reads the TPM protector from `dislocker-metadata -V` output, checks its policy is PolicyAuthValue then PolicyPCR(7, 11),
replays PCR 7 for every list boundary of today's dbx and every db entry, and writes the dbx that matches.

**`fetch`**

Downloads signed dbx updates: `--lvfs` every uefi.org release (needs `zstd`), `--secureboot-objects` every historical
file of Microsoft's repository (needs `git`), `--windows ROOT` the files a mounted Windows volume applied. `--catalog
KB` prints Microsoft Update Catalog links.

**`plan`**

Simulates firmware appends from the factory dbx and searches for the order of updates that rebuilds the target byte for
byte. When none does, it names the first list no update produces.

**`psf`**

Lists and extracts the dbx files of a Windows update's express package: give the inner `Windows10.0-KB...-x64.cab`
(holding `express.psf.cix.xml`) and the `.psf`. The results are PA30 patches.

**`apply-delta`**

Applies a PA30 patch with Microsoft's `msdelta.dll` under Wine, through Python's Windows embeddable `python.exe`.
Patches in `n` folders apply to nothing (omit `--base`); patches in `f` folders apply to the Windows release's base
file.

**`kit`**

Proves by simulation that the sequence rebuilds the target, then writes the kit: the update files in order, the target,
the factory dbx, the expected PK, KEK and db, and `rebuild.sh`.

## The rebuild script

`sudo bash rebuild.sh` on the locked machine, from a Linux stick, after the factory keys were loaded. It stops,
writing nothing, unless: it runs as root, `secureboot-db.service` is masked or absent, PK, KEK and db equal the
sealed state, the firmware is not in Setup Mode, and dbx is the factory list or an earlier step of this rebuild. Each
update is written as an authenticated append (attributes 0x67) and dbx must then reach the exact expected size and
stay a prefix of the target. It can be rerun after a stop. `sudo bash rebuild.sh verify` writes nothing and confirms
dbx equals the target and Secure Boot is on. Every run appends to `rebuild.log` beside the script.

## Walkthrough

1. Boot the locked PC from a Linux stick. Mask the stick's dbx updater first:
   `sudo systemctl mask --now secureboot-db.service`.
2. Save `sudo dislocker-metadata -V <BitLocker partition>` to a file, and copy the efivarfs files SecureBoot,
   SetupMode, PK, KEK, db, dbx and dbxDefault. Copy the TPM event log too
   (`/sys/kernel/security/tpm0/binary_bios_measurements`) to check the PCR 7 model.
3. `analyze`. It must report one MATCH. If none matches, PK, KEK, db or the boot path changed as well, and this tool
   cannot help.
4. `tail -c +5 efivars/dbxDefault-*` is the factory dbx; the target must start with it.
5. `fetch` updates, then `plan`. If a list is missing, find the update Windows applied at that time: a Windows volume
   you own (`fetch --windows`), or a Windows update from the catalog (`fetch --catalog`, then `cabextract`, `psf` and
   `apply-delta`). Rerun `plan` until it rebuilds exactly.
6. `kit`, and copy the kit to the stick.
7. In the firmware: Secure Boot off, save. Clear the Secure Boot keys, save. Load the factory keys, save. Secure Boot
   on, save. Do one change per restart. Never clear the TPM or reset security settings.
8. Boot the stick, `sudo bash rebuild.sh`. On SUCCESS reboot into the stick and run `verify`.
9. On VERIFIED, unplug the stick, start Windows, and save the recovery key with `manage-bde -protectors -get C:`.

## Safety

Nothing writes to the encrypted drive or the TPM. The recovery key keeps working whatever happens. The one step that
can end the no key route is clearing the Secure Boot keys on firmware that then cannot load its factory keys.

## Files

No Microsoft binary is part of this project. Updates are downloaded from LVFS, `microsoft/secureboot_objects` and the
Microsoft Update Catalog; `msdelta.dll` must come from a Windows installation you own.

## See also

`dislocker-metadata`(1), `efi-updatevar`(1), `sbkeysync`(1), `manage-bde` on Windows.
