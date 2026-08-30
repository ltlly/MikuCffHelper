import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.corpus import index_samples


class NmAddressResolutionTests(unittest.TestCase):
    def _index_expected_function(
        self,
        nm_output: str,
        expected_function: dict[str, str] | None = None,
    ) -> dict[str, object]:
        expected_function = expected_function or {"name": "target"}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "fixture.bin"
            binary.write_bytes(b"binary fixture")
            metadata = root / "metadata.json"
            metadata.write_text(
                json.dumps(
                    {
                        binary.name: {
                            "expected_functions": [expected_function],
                        }
                    }
                ),
                encoding="utf-8",
            )

            def fake_tool_output(argv: list[str]) -> str | None:
                if argv[0] == "nm":
                    return nm_output
                if argv[0] == "file":
                    return "test executable"
                self.fail(f"unexpected external command: {argv}")

            binary_description = {
                "format": "ELF",
                "bits": 64,
                "endianness": "little",
                "architecture": "x86-64",
                "object_type": "executable",
            }
            with (
                mock.patch.object(
                    index_samples,
                    "inspect_binary",
                    return_value=binary_description,
                ),
                mock.patch.object(
                    index_samples,
                    "tool_output",
                    side_effect=fake_tool_output,
                ),
            ):
                manifest = index_samples.build_manifest(
                    [binary],
                    root,
                    [metadata],
                    baseline=None,
                    file_tool="file",
                    nm_tool="nm",
                )

        self.assertEqual(len(manifest["entries"]), 1)
        functions = manifest["entries"][0]["expected_functions"]
        self.assertEqual(len(functions), 1)
        return functions[0]

    def test_zero_address_is_a_valid_symbol_address(self):
        function = self._index_expected_function("0000000000000000 T target")

        self.assertEqual(function["symbol_status"], "present")
        self.assertEqual(function["address"], "0x0")

    def test_relocatable_nm_address_declares_loader_base(self):
        function: dict[str, object] = {"name": "target"}

        index_samples.annotate_symbol(function, {"target": {0}}, "relocatable")

        self.assertEqual(function["address"], "0x0")
        self.assertEqual(function["address_source"], "nm")
        self.assertEqual(function["loader_image_base"], "0x0")

    def test_missing_symbol_does_not_gain_an_address(self):
        function = self._index_expected_function("0000000000000010 T other")

        self.assertEqual(function["symbol_status"], "missing")
        self.assertNotIn("address", function)
        self.assertNotIn("symbol_address", function)
        self.assertNotIn("symbol_addresses", function)

    def test_duplicate_name_at_same_address_is_unambiguous(self):
        function = self._index_expected_function(
            "\n".join(
                (
                    "0000000000000010 T target",
                    "0000000000000010 t target",
                )
            )
        )

        self.assertEqual(function["symbol_status"], "present")
        self.assertEqual(function["address"], "0x10")
        self.assertNotIn("symbol_addresses", function)

    def test_duplicate_name_at_different_addresses_is_ambiguous(self):
        function = self._index_expected_function(
            "\n".join(
                (
                    "0000000000000010 T target",
                    "0000000000000020 t target",
                )
            )
        )

        self.assertEqual(function["symbol_status"], "ambiguous")
        self.assertEqual(function["symbol_addresses"], ["0x10", "0x20"])
        self.assertNotIn("address", function)

    def test_declared_matching_address_remains_present(self):
        function = self._index_expected_function(
            "0000000000000010 T target",
            {"name": "target", "address": "0x10"},
        )

        self.assertEqual(function["symbol_status"], "present")
        self.assertEqual(function["address"], "0x10")
        self.assertNotIn("symbol_address", function)

    def test_declared_mismatching_address_is_preserved_and_reported(self):
        function = self._index_expected_function(
            "0000000000000020 T target",
            {"name": "target", "address": "0x10"},
        )

        self.assertEqual(function["symbol_status"], "address-mismatch")
        self.assertEqual(function["address"], "0x10")
        self.assertEqual(function["symbol_address"], "0x20")


if __name__ == "__main__":
    unittest.main()
