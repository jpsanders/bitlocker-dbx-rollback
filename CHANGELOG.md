# Changelog

Versions follow [semantic versioning](https://semver.org). Tags carry the bare version, such as `1.0.0`.

## 1.0.0 (2026-11-20)

- First release. `analyze` finds the dbx a TPM only BitLocker protector (PCRs 7 and 11) was sealed against; `fetch`
  downloads Microsoft signed dbx updates from LVFS, `microsoft/secureboot_objects`, the Update Catalog or a Windows
  volume you own; `plan` finds the update order that rebuilds that dbx byte for byte; `psf` and `apply-delta` recover
  updates that only shipped inside Windows updates; `kit` writes a guarded, logged, rerunnable `rebuild.sh` with a
  read only `verify` mode.
- Built on, and proven by, the recovery of a real laptop locked by an Ubuntu stick's `secureboot-db.service`.
- No Microsoft binaries are bundled; tests use synthetic data.
