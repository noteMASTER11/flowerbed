from __future__ import annotations

import base64
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile


EXPECTED = {
    "platform": "platform",
    "sdk_sandbox": "sdk_sandbox",
    "bluetooth": "bluetooth",
    "media": "media",
    "network_stack": "networkstack",
    "nfc": "nfc",
}


def signer(signature: bytes, seinfo: str) -> bytes:
    return (
        b'<signer signature="'
        + signature.hex().encode()
        + b'"><seinfo value="'
        + seinfo.encode()
        + b'"/></signer>'
    )


def policy(*signers: bytes) -> bytes:
    return b'<?xml version="1.0" encoding="iso-8859-1"?><policy>' + b"".join(
        signers
    ) + b"</policy>"


def der(value: bytes) -> bytes:
    if len(value) >= 0x80:
        raise ValueError("fixture is too large")
    return b"\x30" + bytes((len(value),)) + value


def pem(value: bytes) -> bytes:
    return (
        b"-----BEGIN CERTIFICATE-----\n"
        + base64.b64encode(value)
        + b"\n-----END CERTIFICATE-----\n"
    )


class SelinuxSigningTest(unittest.TestCase):
    def mappings(self):
        sources = {
            role: (f"source-{role}".encode(),) for role in EXPECTED.values()
        }
        sources["shared"] = (b"source-shared",)
        releases = {
            role: f"release-{role}".encode() for role in EXPECTED.values()
        }
        return sources, releases

    def documents(self):
        sources, _releases = self.mappings()
        platform = sources["platform"][0]
        return {
            "SYSTEM/etc/selinux/plat_mac_permissions.xml": policy(
                *(signer(sources[role][0], seinfo) for seinfo, role in EXPECTED.items()),
                signer(b"unrelated-mediashell", "mediashell"),
            ),
            "SYSTEM_EXT/etc/selinux/system_ext_mac_permissions.xml": policy(
                signer(b"unrelated-mediashell", "mediashell")
            ),
            "VENDOR/etc/selinux/vendor_mac_permissions.xml": policy(
                signer(platform, "platform")
            ),
            "PRODUCT/etc/selinux/product_mac_permissions.xml": policy(),
            "ODM/etc/selinux/odm_mac_permissions.xml": policy(),
        }

    def test_rewrites_only_expected_source_certificates_and_preserves_bytes(self):
        from scripts.ubuntu.selinux_signing import rewrite_mac_permissions

        sources, releases = self.mappings()
        documents = self.documents()
        rewritten, evidence = rewrite_mac_permissions(
            documents, sources, releases
        )
        for seinfo, role in EXPECTED.items():
            old = sources[role][0].hex().encode()
            new = releases[role].hex().encode()
            self.assertNotIn(old, b"".join(rewritten.values()))
            self.assertIn(new, rewritten["SYSTEM/etc/selinux/plat_mac_permissions.xml"])
        self.assertIn(
            b"unrelated-mediashell",
            bytes.fromhex(
                rewritten[
                    "SYSTEM_EXT/etc/selinux/system_ext_mac_permissions.xml"
                ]
                .split(b'signature="', 1)[1]
                .split(b'"', 1)[0]
                .decode()
            ),
        )
        expected_vendor = documents[
            "VENDOR/etc/selinux/vendor_mac_permissions.xml"
        ].replace(sources["platform"][0].hex().encode(), releases["platform"].hex().encode())
        self.assertEqual(
            expected_vendor,
            rewritten["VENDOR/etc/selinux/vendor_mac_permissions.xml"],
        )
        self.assertEqual(2, evidence["roles"]["platform"]["occurrences"])
        self.assertEqual(sorted(documents), sorted(evidence["members"]))

    def test_rejects_missing_ambiguous_duplicate_and_unknown_role_mappings(self):
        from scripts.ubuntu.selinux_signing import MacPermissionsError, rewrite_mac_permissions

        sources, releases = self.mappings()
        documents = self.documents()
        cases = {}

        missing = dict(documents)
        missing["SYSTEM/etc/selinux/plat_mac_permissions.xml"] = missing[
            "SYSTEM/etc/selinux/plat_mac_permissions.xml"
        ].replace(signer(sources["nfc"][0], "nfc"), b"")
        cases["missing expected signer"] = (missing, sources, releases)

        ambiguous_sources = dict(sources)
        ambiguous_sources["media"] = sources["platform"]
        cases["ambiguous expected signer"] = (
            documents,
            ambiguous_sources,
            releases,
        )

        duplicate_releases = dict(releases)
        duplicate_releases["media"] = releases["platform"]
        cases["duplicate target certificate"] = (
            documents,
            sources,
            duplicate_releases,
        )

        unknown = dict(documents)
        unknown["SYSTEM_EXT/etc/selinux/system_ext_mac_permissions.xml"] = policy(
            signer(sources["shared"][0], "shared")
        )
        cases["unknown re-signed role"] = (unknown, sources, releases)

        for message, arguments in cases.items():
            with self.subTest(message=message), self.assertRaisesRegex(
                MacPermissionsError, message
            ):
                rewrite_mac_permissions(*arguments)

    def test_rejects_malformed_or_noncanonical_xml_and_wrong_expected_source(self):
        from scripts.ubuntu.selinux_signing import MacPermissionsError, rewrite_mac_permissions

        sources, releases = self.mappings()
        documents = self.documents()
        malformed = dict(documents)
        malformed["SYSTEM/etc/selinux/plat_mac_permissions.xml"] = b"<policy>"
        alternate_quotes = dict(documents)
        alternate_quotes["VENDOR/etc/selinux/vendor_mac_permissions.xml"] = policy(
            signer(sources["platform"][0], "platform")
        ).replace(b'signature="', b"signature='").replace(b'"><seinfo', b"'><seinfo")
        wrong_source = dict(documents)
        wrong_source["VENDOR/etc/selinux/vendor_mac_permissions.xml"] = policy(
            signer(b"wrong-platform", "platform")
        )
        for message, candidate in (
            ("malformed XML", malformed),
            ("canonical signature", alternate_quotes),
            ("expected signer", wrong_source),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                MacPermissionsError, message
            ):
                rewrite_mac_permissions(candidate, sources, releases)

    def test_certificate_pem_and_target_files_rewrite_are_strict(self):
        from scripts.ubuntu.selinux_signing import (
            MacPermissionsError,
            certificate_der_from_pem,
            rewrite_target_files_mac_permissions,
        )

        certificate = der(b"certificate")
        self.assertEqual(certificate, certificate_der_from_pem(pem(certificate)))
        for invalid in (
            b"certificate",
            pem(b"not-der"),
            pem(certificate) + pem(certificate),
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        ):
            with self.subTest(invalid=invalid), self.assertRaises(
                MacPermissionsError
            ):
                certificate_der_from_pem(invalid)

        sources, releases = self.mappings()
        documents = self.documents()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unsigned = root / "unsigned.zip"
            prepared = root / "prepared.zip"
            with zipfile.ZipFile(unsigned, "w") as archive:
                archive.writestr("META/misc_info.txt", b"unchanged")
                archive.writestr("IMAGES/large.img", b"x" * (2 * 1024 * 1024))
                for name, value in documents.items():
                    archive.writestr(name, value)
            evidence = rewrite_target_files_mac_permissions(
                unsigned, prepared, sources, releases
            )
            with zipfile.ZipFile(prepared) as archive:
                self.assertEqual(b"unchanged", archive.read("META/misc_info.txt"))
                self.assertEqual(
                    b"x" * (2 * 1024 * 1024), archive.read("IMAGES/large.img")
                )
                self.assertIn(
                    releases["platform"].hex().encode(),
                    archive.read("SYSTEM/etc/selinux/plat_mac_permissions.xml"),
                )
            self.assertEqual(sorted(documents), sorted(evidence["members"]))

            duplicate = root / "duplicate.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(duplicate, "w") as archive:
                    for name, value in documents.items():
                        archive.writestr(name, value)
                    archive.writestr(
                        "SYSTEM/etc/selinux/plat_mac_permissions.xml",
                        documents["SYSTEM/etc/selinux/plat_mac_permissions.xml"],
                    )
            with self.assertRaisesRegex(MacPermissionsError, "duplicate"):
                rewrite_target_files_mac_permissions(
                    duplicate, root / "rejected.zip", sources, releases
                )


if __name__ == "__main__":
    unittest.main()
