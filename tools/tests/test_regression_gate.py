import copy
import unittest

from tools.regression_test import (
    diff_against_baseline,
    evaluate_gate,
    validate_baseline_document,
)


def safe_result(**updates):
    result = {
        "status": "ok",
        "name": "sub_1000",
        "hlil": 10,
        "switch": True,
        "deflated": False,
        "orphan": False,
        "se_lost": 0,
        "mlil_calls_lost": 0,
        "mlil_stores_lost": 0,
        "mlil_rets_lost": 0,
        "hlil_calls_lost": 0,
        "hlil_stores_lost": 0,
        "hlil_rets_lost": 0,
    }
    result.update(updates)
    return result


def make_baseline():
    return {
        "schema_version": 2,
        "manifest": {
            "schema_version": 1,
            "function_timeout_seconds": 5,
            "samples": [
                {
                    "binary": "sample.so",
                    "sha256": "0" * 64,
                    "functions": ["0x1000"],
                }
            ],
        },
        "summary": {"total": 1},
        "report": [
            {
                "binary": "sample.so",
                "results": {"0x1000": safe_result()},
            }
        ],
    }


class StrictGateTests(unittest.TestCase):
    def test_empty_report_is_failure(self):
        errors, _, _ = evaluate_gate([], make_baseline())
        self.assertTrue(any("缺失预期函数" in error for error in errors), errors)

        legacy_errors, _ = diff_against_baseline(
            [], make_baseline()["report"]
        )
        self.assertTrue(
            any("缺失 baseline 函数" in error for error in legacy_errors),
            legacy_errors,
        )

    def test_unknown_current_key_is_failure(self):
        report = [
            {
                "binary": "sample.so",
                "results": {"0x2000": safe_result(name="sub_2000")},
            }
        ]
        errors, _, _ = evaluate_gate(report, make_baseline())
        self.assertTrue(any("未请求函数" in error for error in errors), errors)
        self.assertTrue(any("缺失预期函数" in error for error in errors), errors)

    def test_manifest_and_baseline_key_sets_must_match(self):
        baseline = make_baseline()
        baseline["report"][0]["results"]["0x2000"] = safe_result()
        errors = validate_baseline_document(baseline)
        self.assertTrue(any("manifest 外函数" in error for error in errors), errors)

        baseline = make_baseline()
        baseline["report"][0]["results"].clear()
        errors = validate_baseline_document(baseline)
        self.assertTrue(any("缺失 manifest 函数" in error for error in errors), errors)

    def test_manual_counterexample_fails_even_when_unmanifested_allowed(self):
        # arm64-v8a.so:0x4259f4 的实际观测：SE_LOST=3、store=2、ret=1。
        manual = safe_result(
            name="sub_4259f4",
            se_lost=3,
            hlil_stores_lost=2,
            hlil_rets_lost=1,
        )
        report = [
            {
                "binary": "arm64-v8a.so",
                "results": {"0x4259f4": manual},
            }
        ]
        errors, _, _ = evaluate_gate(
            report,
            make_baseline(),
            {"arm64-v8a.so:0x4259f4"},
            allow_unmanifested=True,
        )
        self.assertTrue(any("MLIL 副作用丢失 3" in e for e in errors), errors)
        self.assertTrue(any("HLIL store 丢失 2" in e for e in errors), errors)
        self.assertTrue(any("HLIL return 丢失 1" in e for e in errors), errors)

    def test_timeout_error_and_orphan_are_absolute_failures(self):
        for result, marker in (
            (safe_result(status="timeout", error="budget exceeded"), "status=timeout"),
            (safe_result(status="error", error="boom"), "status=error"),
            (safe_result(orphan=True), "ORPHAN"),
            (safe_result(mlil_calls_lost=1), "MLIL call 丢失 1"),
            (safe_result(hlil_calls_lost=1), "HLIL call 丢失 1"),
        ):
            with self.subTest(marker=marker):
                baseline = make_baseline()
                report = [
                    {
                        "binary": "sample.so",
                        "results": {"0x1000": copy.deepcopy(result)},
                    }
                ]
                errors, _, _ = evaluate_gate(report, baseline)
                self.assertTrue(any(marker in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
