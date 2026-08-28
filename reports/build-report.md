# LineageOS 23.2 fleur build report

- Date: 2026-08-28
- Product: `lineage_fleur-userdebug`
- Platform: LineageOS 23.2 / Android 16
- Evidence level: build-verified

## Successful build targets

| Target | Result | Final incremental pass |
| --- | --- | ---: |
| Recovery OTA | Passed | 00:12:54 |
| `updatepackage` | Passed | 00:11:01 |
| `superimage` | Passed | 00:02:11 |

The final passes reused the existing Ninja output and compiler cache. No clean build was performed after the compatibility patches.

## Build artifacts

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `lineage-23.2-20260828-UNOFFICIAL-fleur.zip` | 1,149,239,829 | `e5ea8d0130f412b17ef2f921f66052f34c43cf3f5c6d6932105175812510364d` |
| `boot.img` | 67,108,864 | `3ba16d605d41293c5dec40e1432bc9aef4077f2bf3735821290da6d39025c881` |
| `firmware-fleur-OS1.0.10.0.TKEINXM.zip` | 42,981,451 | `2c0edf8e9d28f78307b11f5ae828c0f3f0a7134f1206fa9450a8d0fa6347e6d2` |
| `lineage_fleur-img.zip` | 1,410,001,592 | `59a7c5a92e9e7afd0ad92466f5102021a4d5a91a5de07305a09b3e618fcfb4ff` |
| `lineage-23.2-20260828-UNOFFICIAL-fleur-spft-reference.zip` | 2,548,891,221 | `cd49770f2d3bbf33b27b1e8ab02cc507cb47375b1ff060eec6c2f4f6a0eaf575` |

These binary artifacts are not stored in Git. The table records the local verified build outputs used during bring-up.

## Static verification

- all repository unit tests passed;
- Recovery OTA ZIP integrity passed;
- target metadata identified `fleur`;
- `payload.bin` was present;
- all eleven firmware partitions matched `sources/firmware.json`;
- fastboot ZIP contained the required boot, DTBO, AVB, super, and firmware images;
- SPFT package image sizes fit the official MT6781/fleur partition limits;
- the SPFT Download-XML referenced the packaged scatter and official Download Agent.

## Compatibility fixes

The successful build applies the five patches in `patches/series`: the MediaTek memtrack module rename and four removals of device-local SELinux declarations already supplied by common MediaTek policy.

See the Russian [GitHub Wiki](https://github.com/noteMASTER11/flowerbed/wiki) for the complete build and troubleshooting instructions.
