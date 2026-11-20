# Security

## Reporting a vulnerability

Please report security problems privately, through GitHub's
[private vulnerability reporting](https://github.com/jpsanders/bitlocker-dbx-rollback/security/advisories/new), not in a
public issue. You will get an answer within a week.

## What this tool does, and does not do

It does not break BitLocker. It cannot unlock a drive whose TPM would not have unlocked it in its original boot state:
it only restores the firmware's dbx to a state the owner's own machine was already in, so the owner's own TPM releases
the key as it did before. It needs physical access, the firmware's administrator access, and a working TPM protector.

`analyze`, `plan`, `fetch`, `psf` and `apply-delta` read files and write only to the paths given. The kit's
`rebuild.sh` runs as root and writes one UEFI variable, dbx, with signed append updates; it never writes to a disk or
the TPM.
