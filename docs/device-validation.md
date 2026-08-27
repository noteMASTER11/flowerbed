# fleur device validation

## Evidence levels

- **Build-verified:** host tests and full payload verification passed.
- **Install-verified:** recovery accepted the OTA and the device reached the
  setup wizard.
- **Device-tested:** the smoke-test matrix below passed on physical hardware.

Until the last level is reached, the repository and release notes must call the
ROM experimental and must not imply physical-device validation.

## Read-only preflight

With Android booted and USB debugging authorized:

```bash
cd ~/src/flowerbed
scripts/ubuntu/collect_device_logs.sh reports/private/device/pre-install
```

The collector requests only an allowlisted set of properties and diagnostics.
It does not call reboot, sideload, flash, erase, wipe, or `adb get-serialno`.
Outputs under `reports/private/` are Git-ignored because logs may contain local
network names, account-related data, or other identifiers.

Confirm manually:

```bash
adb shell getprop ro.product.device
adb shell getprop ro.boot.hwc
adb shell getprop ro.miui.build.region
adb shell ls -l /dev/block/bootdevice/by-name
```

Expected product device: `fleur`. Record the hardware/region result; do not infer
it from the model name.

## Post-install collection

After the first successful boot and USB-debugging authorization:

```bash
cd ~/src/flowerbed
scripts/ubuntu/collect_device_logs.sh reports/private/device/post-install
```

Check that `sys.boot_completed=1`, `ro.crypto.state=encrypted`, SELinux is
enforcing, and no repeating fatal crash or boot loop appears in logcat.

## Smoke-test matrix

Record pass, fail, or not tested for each item and include relevant sanitized log
references in the release report.

| Area | Test |
| --- | --- |
| Boot | Cold boot, warm reboot, recovery reboot, both slots visible |
| Encryption | Lock screen, data remains readable after reboot |
| SIM and radio | SIM detection, mobile data, outgoing/incoming call, SMS |
| IMS | VoLTE and VoWiFi where carrier provisioning supports them |
| Wi-Fi | 2.4 GHz and 5 GHz association, reconnect after reboot |
| Bluetooth | Pairing, media audio, call audio |
| Audio | Speaker, receiver, microphones, wired/USB audio if available |
| Camera | Front/rear photo, video, flashlight, third-party camera client |
| Display | Brightness, rotation, refresh-rate modes, touch and gestures |
| Sensors | Proximity during call, accelerometer, compass, fingerprint |
| Location | GNSS fix and application permission behavior |
| USB | ADB, MTP/file transfer, charging indication |
| Power | Deep sleep, charging, battery percentage across reboot |
| Storage | Internal storage, adoptable/removable media if present |
| DRM/media | Widevine level, protected playback where legitimately available |
| Stability | At least one hour mixed use without reboot or system_server loop |

## Failure evidence

Preserve the verified OTA SHA-256, resolved manifest snapshot, build metadata,
pre/post diagnostic directories, recovery log, exact reproduction steps, and the
active slot. Redact identifiers before publishing any report.
