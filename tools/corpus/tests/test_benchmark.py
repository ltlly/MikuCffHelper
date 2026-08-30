import unittest

from tools.corpus import benchmark


SHA256 = "a" * 64


def manifest_entry(
    path: str,
    expected_functions: list[dict[str, object]],
    **extra: object,
) -> dict[str, object]:
    return {
        "path": path,
        "sha256": SHA256,
        "expected_functions": expected_functions,
        **extra,
    }


class TargetSelectionTests(unittest.TestCase):
    def test_manifest_address_zero_is_selected(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "zero.bin",
                    [{"name": "entry_at_zero", "address": 0}],
                )
            ]
        }

        targets = benchmark.select_targets(manifest, [])

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["binary"], "zero.bin")
        self.assertEqual(targets[0]["address"], "0x0")

    def test_manifest_loader_base_is_carried_to_measurement(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "zero.bin",
                    [
                        {
                            "name": "entry_at_zero",
                            "address": "0x0",
                            "loader_image_base": "0x0",
                        }
                    ],
                )
            ]
        }

        target = benchmark.select_targets(manifest, ["zero.bin@0"])[0]

        self.assertEqual(target["address"], "0x0")
        self.assertEqual(target["loader_image_base"], "0x0")

    def test_default_selection_uses_only_expected_functions(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "declared.bin",
                    [{"name": "declared", "address": "0x10"}],
                    role="negative",
                    flattening_score=0.0,
                    cff_candidate=False,
                ),
                manifest_entry(
                    "role-only.bin",
                    [],
                    role="positive",
                    flattening_score=1.0,
                    cff_candidate=True,
                    detected_functions=[{"name": "not_declared", "address": "0x20"}],
                ),
            ]
        }

        targets = benchmark.select_targets(manifest, [])

        self.assertEqual(
            [(target["binary"], target["address"]) for target in targets],
            [("declared.bin", "0x10")],
        )

    def test_requested_target_is_an_exact_path_and_address_filter(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "first.bin",
                    [
                        {"name": "first_10", "address": "0x10"},
                        {"name": "first_20", "address": "0x20"},
                    ],
                ),
                manifest_entry(
                    "second.bin",
                    [{"name": "second_20", "address": "0x20"}],
                ),
            ]
        }

        targets = benchmark.select_targets(manifest, ["first.bin@0x20"])

        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["binary"], "first.bin")
        self.assertEqual(targets[0]["address"], "0x20")
        self.assertEqual(targets[0]["manifest_name"], "first_20")

    def test_duplicate_requested_target_fails_after_address_normalization(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "fixture.bin",
                    [{"name": "target", "address": "0x10"}],
                )
            ]
        }

        with self.assertRaisesRegex(
            benchmark.ManifestError,
            r"duplicate requested target: fixture\.bin@0x10",
        ):
            benchmark.select_targets(
                manifest,
                ["fixture.bin@0x10", "fixture.bin@16"],
            )

    def test_duplicate_manifest_target_fails(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "fixture.bin",
                    [
                        {"name": "first", "address": "0x10"},
                        {"name": "alias", "address": 16},
                    ],
                )
            ]
        }

        with self.assertRaisesRegex(
            benchmark.ManifestError,
            r"duplicate manifest target: fixture\.bin@0x10",
        ):
            benchmark.select_targets(manifest, [])

    def test_duplicate_manifest_binary_fails(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "fixture.bin",
                    [{"name": "first", "address": "0x10"}],
                ),
                manifest_entry(
                    "fixture.bin",
                    [{"name": "second", "address": "0x20"}],
                ),
            ]
        }

        with self.assertRaisesRegex(
            benchmark.ManifestError,
            r"duplicate manifest binary: fixture\.bin",
        ):
            benchmark.select_targets(manifest, [])

    def test_declared_function_without_address_fails(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "fixture.bin",
                    [{"name": "name_is_not_an_address"}],
                )
            ]
        }

        with self.assertRaisesRegex(
            benchmark.ManifestError,
            r"expected function 'name_is_not_an_address' has no address",
        ):
            benchmark.select_targets(manifest, [])

    def test_requested_target_not_in_manifest_fails(self):
        manifest = {
            "entries": [
                manifest_entry(
                    "fixture.bin",
                    [{"name": "target", "address": "0x10"}],
                )
            ]
        }

        for target in ("fixture.bin@0x20", "missing.bin@0x10"):
            with self.subTest(target=target), self.assertRaisesRegex(
                benchmark.ManifestError,
                r"requested target is not declared in manifest",
            ):
                benchmark.select_targets(manifest, [target])


if __name__ == "__main__":
    unittest.main()
