# SP Flash Tool V6 reference package

This repository can package the verified LineageOS output and pinned fleur
firmware as a separate SP Flash Tool V6 reference archive. The 2026-08-28
package was reported by the operator as accepted by SP Flash Tool, flashed, and
booted on a physical device. Packaging itself does not flash a device, and a
successful boot is not a replacement for the full smoke-test matrix.

## Inputs

- `boot.img`, `dtbo.img`, `vbmeta.img`, `vbmeta_system.img`,
  `vbmeta_vendor.img`, and `super.img` from the same successful LineageOS build;
- the eleven pinned firmware images recorded in `sources/firmware.json`;
- `MT6781_Android_scatter.xml` from the official fleur fastboot image package,
  used only as the partition-address and partition-size template.
- `download_agent/flash.xml`, `download_agent/flash.xsd`, and
  `download_agent/DA_BR.bin` from that same official package. The download agent
  is required by SP Flash Tool V6 and is not an authentication file.

The packager preserves the official MT6781/fleur addresses and limits. It
rejects an image that exceeds its declared partition size. Every template entry
is disabled first; only the approved A-slot images and `super` are then enabled.
The preloader, preloader backup, `cust`, `rescue`, `userdata`, B-slot, and any
unknown entries remain disabled. `preloader_raw.img` is included for provenance
but is not mapped to either preloader partition.

## Create the package

```bash
python3 scripts/ubuntu/package_spft.py \
  --scatter-xml /mnt/c/fleur_ru_global_images_V14.0.6.0.TKERUXM_13.0/images/MT6781_Android_scatter.xml \
  --product-out ~/android/lineage-23.2/out/target/product/fleur \
  --firmware-dir ~/android/lineage-23.2/vendor/xiaomi/fleur/radio \
  --firmware-manifest ~/src/flowerbed/sources/firmware.json \
  --download-agent-dir /mnt/c/fleur_ru_global_images_V14.0.6.0.TKERUXM_13.0/images/download_agent \
  --output-dir /mnt/c/output \
  --name lineage-23.2-UNOFFICIAL-fleur-spft-reference
```

The result contains:

- `images/download_agent/flash.xml`, the SP Flash Tool V6 Download-XML;
- `images/download_agent/DA_BR.bin`, the required official download agent;
- `images/MT6781_Android_scatter.xml`, referenced by `flash.xml`;
- the enabled LineageOS and pinned firmware images;
- the deliberately unmapped `preloader_raw.img` provenance image;
- `README.txt` and `SHA256SUMS`;
- a ZIP containing the same directory tree.

## SP Flash Tool fields

Choose `images/download_agent/flash.xml` in the **Download-XML** field. No
authentication file is required for this package; leave **Authentication File**
blank. Use **Download Only** and independently confirm that the UI reports
platform `MT6781` and project `fleur` before connecting a device.

Do not use **Format All + Download**. The 2026-08-28 package reached the
install-verified level; keep subsequent binaries labeled build-verified until
their own physical installation has been confirmed. Use
`docs/device-validation.md` before describing any build as fully device-tested.
