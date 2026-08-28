# fleur source provenance

Retrieved: 2026-08-27

## Source sets

| ID | ROM | Status | Repositories | Evidence | Notes |
| --- | --- | --- | --- | --- | --- |
| `crdroid-12.11` | crDroid 12.11 | `verified-current` | `device/xiaomi/fleur` → `mt6781-devs/android_device_xiaomi_fleur@lineage-23.2`<br>`kernel/xiaomi/mt6781` → `mt6781-devs/android_kernel_xiaomi_mt6781@lineage-23.2`<br>`vendor/xiaomi/fleur` → `z3rh0/proprietary_vendor_xiaomi_fleur@lineage-23.2` | [source 1](https://github.com/StasGr12/crDroid-fleur)<br>[source 2](https://github.com/StasGr12/crDroid-fleur/releases/tag/v12.11) | Published 2026 device build using the same device, vendor, and clean kernel branches. Its ROM platform is not reused. |
| `infinity-x-3.12-v3` | Project Infinity X 3.12 v3 | `modified` | `device/xiaomi/fleur` → `mt6781-devs/android_device_xiaomi_fleur@lineage-23.2`<br>`kernel/xiaomi/mt6781` → `StasGr12/android_kernel_xiaomi_mt6781@lineage-23.2-ksun-susfs`<br>`vendor/xiaomi/fleur` → `z3rh0/proprietary_vendor_xiaomi_fleur@lineage-23.2` | [source 1](https://github.com/StasGr12/Infinity-X-Fleur)<br>[source 2](https://github.com/StasGr12/Infinity-X-Fleur/releases/tag/v3.12-v3) | Recent device evidence with a KernelSU/SUSFS kernel; the modified kernel is excluded from the clean baseline. |
| `lineage-20-historical` | LineageOS 20 historical tree | `historical` | `device/xiaomi/fleur` → `xiaomi-mt6781-fleur-dev/android_device_xiaomi_fleur@lineage-20.0` | [source 1](https://github.com/xiaomi-mt6781-fleur-dev/android_device_xiaomi_fleur/tree/lineage-20.0) | Historical dependency and partition-layout reference only. |
| `lineage-23.2-baseline` | LineageOS 23.2 candidate baseline | `candidate-current` | `device/mediatek/sepolicy_vndr` → `mt6781-devs/android_device_mediatek_sepolicy_vndr@dc6d099b7a1b85a38151b80e675684888ef22683`<br>`device/xiaomi/fleur` → `mt6781-devs/android_device_xiaomi_fleur@45289f6f6e94fc90870d27477d42a89c735fcff5`<br>`hardware/mediatek` → `mt6781-devs/android_hardware_mediatek@8d18fc6d5b3a63fe2abf9e935947f71c484db291`<br>`hardware/xiaomi` → `LineageOS/android_hardware_xiaomi@1ad18efb60bc5c3cf794213fb29822837e38c1f8`<br>`kernel/xiaomi/mt6781` → `mt6781-devs/android_kernel_xiaomi_mt6781@9996b68a1808b38f2f9e7798b26479e721bc2a84`<br>`vendor/xiaomi/fleur` → `z3rh0/proprietary_vendor_xiaomi_fleur@9430b0e8c9e7915fcac5257c21d1c539acaf94c6` | [source 1](https://github.com/mt6781-devs/android_device_xiaomi_fleur/tree/lineage-23.2)<br>[source 2](https://github.com/z3rh0/proprietary_vendor_xiaomi_fleur/tree/lineage-23.2)<br>[source 3](https://github.com/LineageOS/android_hardware_xiaomi/tree/lineage-23.2) | Clean candidate baseline. The exact branch heads were reachable on 2026-08-27; build and device validation are separate gates. |

## Bounded forum and archive findings

- **4PDA:** The fleur topic header inspected at offset st=2620 lists current Android 16 ROMs but not LineageOS 23.x; the topic search returned no LineageOS 23.1 result. ([source 1](https://4pda.to/forum/index.php?showtopic=1070596&st=2620))
- **XDA:** No current LineageOS 23.x source/build thread for fleur was located by the bounded searches performed on 2026-08-27. Returned fleur results were support or recovery threads, not reproducible ROM source sets. ([source 1](https://xdaforums.com/t/hotspot-wifi-bluetooth-not-working-when-root.4643745/), [source 2](https://xdaforums.com/t/from-miui-to-hyperos-problem.4686626/))
- **Xiaomi Firmware Updater:** The complete fleur archive contains regional Global, EEA, India, Indonesia, Russia, and other historical packages. The current pinned vendor images were compared against the latest archived Android 13 packages. ([source 1](https://xmfirmwareupdater.com/archive/firmware/fleur/))

## Firmware payload

Pinned vendor: `z3rh0/proprietary_vendor_xiaomi_fleur@9430b0e8c9e7915fcac5257c21d1c539acaf94c6`

Archive match: `OS1.0.10.0.TKEINXM` (India); package SHA-256 `ece414deac942f8fc55bcb8f1ece0b386feca4a0088cc1bf125fe59c87844fc6` ([download](https://github.com/XiaomiFirmwareUpdaterReleases/firmware_xiaomi_fleur/releases/download/stable-28.12.2024/fw_fleur_miui_FLEURINGlobal_OS1.0.10.0.TKEINXM_8680e64fbe_13.0.zip)).

| Partition | Vendor file | Bytes | SHA-256 | XFU prefix match |
| --- | --- | ---: | --- | --- |
| `audio_dsp` | `radio/audio_dsp.img` | 822000 | `ada0e592f8aebe7fd5ef62298397b2fcbd2d5dfc9557e80b7d6c2df074833238` | yes |
| `gz` | `radio/gz.img` | 2877248 | `10115cb17768ed54f8f4c8f654b15d6bc6a622f4a42a8a6c84c1f381b934e489` | yes |
| `lk` | `radio/lk.img` | 1688704 | `5ae6e6ba6267532b8d766a3ee12f92b902eec2e5b0f94839fbac2ba699b5c44c` | yes |
| `logo` | `radio/logo.img` | 4140736 | `f34e0bcd2a07c5c39b7e27299e7e9ce4a39a044f83f9c98b9a687bb471a1e88b` | not present in comparison ZIP |
| `md1img` | `radio/md1img.img` | 53395200 | `e3383a8e7a1eb471f3b85469ceec75051d4a3cdb9991fbe02764a9ffdf005c9e` | yes |
| `pi_img` | `radio/pi_img.img` | 5328 | `3d5ac0658abbf10da2b1578d21a73defae3cc4c169cc5b552add368acadec0e7` | yes |
| `preloader_raw` | `radio/preloader_raw.img` | 360920 | `8e3755f74ebcb05849715e217d425fa559a4904f246945d89e5078836aa055df` | yes |
| `scp` | `radio/scp.img` | 871456 | `a3d16cb458b2975e62e5fe689f36445f06ca24c06bcf500cc4d3e8ea85aec740` | yes |
| `spmfw` | `radio/spmfw.img` | 16672 | `dc3c8ef2b18a160a1210aea0485082c0806fd4b1f7a1bfd2bd267179214e846b` | yes |
| `sspm` | `radio/sspm.img` | 676720 | `b2859cd77c1392766f0b46c91aec573f341ddb51d21db8455f2de14b345bce36` | yes |
| `tee` | `radio/tee.img` | 2614496 | `92366b832392468411018ce4e46a41bcdba430b6de06d57d2d34b39d911defaf` | yes |

Metadata discrepancy: The device-tree comment names Global V816.0.9.0.TKEMIXM, while ten current vendor images match the archived India OS1.0.10.0.TKEINXM package after trailing-padding normalization; logo.img is present only in the pinned vendor comparison set.
