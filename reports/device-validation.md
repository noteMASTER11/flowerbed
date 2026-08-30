# fleur device validation report

- Date: 2026-08-28
- Evidence source: operator report
- Highest confirmed level: install-verified

## Confirmed

- SP Flash Tool V6 accepted `images/download_agent/flash.xml` with the Authentication File field left blank.
- The generated package was flashed to a physical `fleur` device.
- The device booted the installed system.

## Not yet recorded as passed

The repository does not contain a completed public smoke-test matrix for radio, IMS, Wi-Fi, Bluetooth, audio, cameras, display, sensors, GNSS, USB, power, storage, DRM, encryption, SELinux, or long-duration stability.

Therefore this build is **install-verified**, not fully **device-tested**. Future releases must repeat installation validation and complete the protocol in `docs/device-validation.md`; validation status does not automatically carry over to a new binary.
