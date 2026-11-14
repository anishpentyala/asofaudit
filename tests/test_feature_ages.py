"""Independent mixed-feature age-policy oracles and fail-closed interfaces."""

import contextlib
import csv
import hashlib
import io
import json
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asofaudit import AuditError, audit
from asofaudit.cli import main

DAY = 86400000000
HEADERS = {
    "history": ["version_id", "entity_id", "feature", "event_at", "known_at"],
    "requests": ["request_id", "entity_id", "prediction_at"],
    "selections": ["request_id", "feature", "version_id"],
}


def time(day):
    return "2024-01-%02dT00:00:00Z" % day


class FeatureAgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.features = ["balance", "plan"]
        self.history = [
            ["b", "a", "balance", time(1), time(1)],
            ["p", "a", "plan", time(1), time(1)],
        ]
        self.requests = [["r", "a", time(3)]]
        self.selections = [["r", "balance", "b"], ["r", "plan", "p"]]

    def paths(self):
        paths = []
        for name, header in HEADERS.items():
            path = self.root / (name + ".csv")
            with path.open("w", newline="", encoding="utf8") as stream:
                writer = csv.writer(stream)
                writer.writerow(header)
                writer.writerows(getattr(self, name))
            paths.append(path)
        return paths

    def run_audit(self, **kwargs):
        opts = dict(features=self.features, examples=1000, temp_dir=self.scratch)
        opts.update(kwargs)
        row = audit(*self.paths(), **opts)
        self.assertEqual(list(self.scratch.iterdir()), [])
        return row

    def test_different_limits_and_explicit_unlimited(self):
        for plan_limit in (None, 2 * DAY):
            row = self.run_audit(
                feature_max_age_us={"balance": DAY, "plan": plan_limit}
            )
            self.assertEqual(row["reasons"], {"expired": 1})
            self.assertEqual(row["expected_missing"], 1)
            self.assertEqual(row["examples"][0]["feature"], "balance")
            self.assertEqual(
                row["policy"]["feature_max_age_us"],
                {"balance": DAY, "plan": plan_limit},
            )
            self.assertIsNone(row["policy"]["max_age_us"])

    def test_exact_microsecond_age_and_zero(self):
        self.requests[0][-1] = "2024-01-01T01:00:00.000001+01:00"
        for limit, reason in ((0, {"expired": 1}), (1, {}), (2, {})):
            row = self.run_audit(feature_max_age_us={"balance": limit, "plan": None})
            self.assertEqual(row["reasons"], reason)
        self.requests[0][-1] = time(1)
        self.assertTrue(
            self.run_audit(feature_max_age_us={"balance": 0, "plan": 0})["ok"]
        )

    def test_known_clock_still_applies_to_unlimited_feature(self):
        self.history.append(["correction", "a", "plan", time(2), time(4)])
        self.selections[1][-1] = "correction"
        row = self.run_audit(feature_max_age_us={"balance": None, "plan": None})
        self.assertEqual(row["reasons"], {"not_yet_known": 1})
        self.assertEqual(row["examples"][0]["expected_version"], "p")

    def test_reason_precedence_under_feature_expiry(self):
        extras = [
            (["entity", "z", "balance", time(1), time(1)], "wrong_entity"),
            (["feature", "a", "other", time(1), time(1)], "wrong_feature"),
            (["future", "a", "balance", time(4), time(1)], "future_event"),
            (["unknown", "a", "balance", time(1), time(4)], "not_yet_known"),
        ]
        for version, reason in extras:
            with self.subTest(reason=reason):
                self.history = self.history[:2] + [version]
                self.selections[0][-1] = version[0]
                self.assertEqual(
                    self.run_audit(feature_max_age_us={"balance": 0, "plan": None})[
                        "reasons"
                    ],
                    {reason: 1},
                )

    def test_invalid_complete_policy_before_io(self):
        invalid = [
            [],
            "balance",
            1,
            True,
            {},
            {"balance": 0},
            {"balance": 0, "plan": None, "extra": 1},
        ]
        for value in (-1, True, False, 1.0, "1", [], {}, 315537897600000000):
            invalid.append({"balance": value, "plan": None})
        for policy in invalid:
            with self.subTest(policy=policy):
                with patch(
                    "asofaudit.core.tempfile.TemporaryDirectory",
                    side_effect=AssertionError("must validate before scratch"),
                ):
                    with self.assertRaises(AuditError):
                        audit(
                            "absent",
                            "absent",
                            "absent",
                            features=self.features,
                            feature_max_age_us=policy,
                        )
        with self.assertRaisesRegex(AuditError, "mutually exclusive"):
            self.run_audit(
                max_age_us=0, feature_max_age_us={"balance": 0, "plan": None}
            )

    def test_extra_policy_feature_is_not_ignored(self):
        with self.assertRaisesRegex(AuditError, "exactly requested"):
            self.run_audit(
                feature_max_age_us={"balance": None, "plan": None, "typo": 0}
            )

    def test_mapping_snapshot_before_input_consumption(self):
        from asofaudit import core

        original = core._rows
        policy = {"balance": 0, "plan": None}

        @contextlib.contextmanager
        def changing(*args, **kwargs):
            policy["balance"] = None
            with original(*args, **kwargs) as rows:
                yield rows

        with patch("asofaudit.core._rows", changing):
            row = self.run_audit(feature_max_age_us=policy)
        self.assertEqual(row["reasons"], {"expired": 1})
        self.assertEqual(
            row["policy"]["feature_max_age_us"], {"balance": 0, "plan": None}
        )

    def test_maximum_supported_age_and_empty_history(self):
        policy = {"balance": 315537897599999999, "plan": None}
        self.assertTrue(self.run_audit(feature_max_age_us=policy)["ok"])
        self.history = []
        self.selections = [["r", f, ""] for f in self.features]
        row = self.run_audit(feature_max_age_us=policy)
        self.assertTrue(row["ok"])
        self.assertEqual(row["expected_missing"], 2)

    def test_caller_mapping_copied_and_exact_feature_names(self):
        self.features = ["x=y", 'space "❄"']
        for i in range(2):
            self.history[i][2] = self.features[i]
            self.selections[i][1] = self.features[i]
        policy = dict.fromkeys(self.features, None)
        row = self.run_audit(feature_max_age_us=policy)
        policy[self.features[0]] = 0
        self.assertEqual(
            row["policy"]["feature_max_age_us"], dict.fromkeys(self.features, None)
        )
        self.assertTrue(row["ok"])

    def test_uniform_policy_identical_to_global_except_declaration(self):
        for limit in (None, 0, DAY, 2 * DAY, 315537897599999999):
            global_row = self.run_audit(max_age_us=limit)
            row = self.run_audit(feature_max_age_us=dict.fromkeys(self.features, limit))
            self.assertEqual(
                row["policy"].pop("feature_max_age_us"),
                dict.fromkeys(self.features, limit),
            )
            row["policy"]["max_age_us"] = limit
            self.assertEqual(row, global_row)
            self.assertNotIn("feature_max_age_us", global_row["policy"])

    def test_independent_mixed_feature_full_report_oracle(self):
        rng = random.Random(271828)
        self.features = ["g", "f", "h"]
        for case in range(100):
            history = []
            self.history = []
            for n in range(rng.randrange(25)):
                entity, feature, event, known = (
                    rng.choice(["a", "b"]),
                    rng.choice(self.features),
                    rng.randrange(1, 8),
                    rng.randrange(1, 9),
                )
                if any(
                    (e, f, ev, kn) == (entity, feature, event, known)
                    for _, e, f, ev, kn in history
                ):
                    continue
                version = "v%s" % n
                history.append((version, entity, feature, event, known))
                self.history.append(
                    [version, entity, feature, time(event), time(known)]
                )
            requests = [
                ("r%s" % i, rng.choice(["a", "b", "c"]), rng.randrange(1, 10))
                for i in range(8)
            ]
            self.requests = [[r, e, time(t)] for r, e, t in requests]
            policies = {
                f: rng.choice([None, 0, DAY - 1, DAY, 2 * DAY]) for f in self.features
            }
            selected = {
                (r, f): rng.choice([""] + [v[0] for v in history])
                for r, _, _ in requests
                for f in self.features
            }
            self.selections = [[r, f, v] for (r, f), v in selected.items()]
            rng.shuffle(self.history)
            rng.shuffle(self.requests)
            rng.shuffle(self.selections)
            evidence, reasons, absent = [], {}, 0
            by_feature = {
                f: dict(checked=0, violations=0, expected_missing=0)
                for f in self.features
            }
            for request, entity, when in sorted(requests):
                for feature in self.features:
                    age = policies[feature]
                    eligible = [
                        v
                        for v in history
                        if v[1] == entity
                        and v[2] == feature
                        and v[3] <= when
                        and v[4] <= when
                        and (age is None or (when - v[3]) * DAY <= age)
                    ]
                    winner = (
                        max(eligible, key=lambda v: (v[3], v[4]))[0] if eligible else ""
                    )
                    choice = selected[request, feature]
                    reason = None
                    if choice != winner:
                        if not choice:
                            reason = "missing_selection"
                        else:
                            v, e, f, ev, kn = next(v for v in history if v[0] == choice)
                            if e != entity:
                                reason = "wrong_entity"
                            elif f != feature:
                                reason = "wrong_feature"
                            elif ev > when:
                                reason = "future_event"
                            elif kn > when:
                                reason = "not_yet_known"
                            elif age is not None and (when - ev) * DAY > age:
                                reason = "expired"
                            else:
                                reason = "not_latest"
                    by_feature[feature]["checked"] += 1
                    if not winner:
                        absent += 1
                        by_feature[feature]["expected_missing"] += 1
                    if reason:
                        reasons[reason] = reasons.get(reason, 0) + 1
                        by_feature[feature]["violations"] += 1
                        evidence.append(
                            dict(
                                request_id=request,
                                feature=feature,
                                selected_version=choice,
                                expected_version=winner,
                                reason=reason,
                            )
                        )
            row = self.run_audit(feature_max_age_us=policies, examples=7)
            inputs = {}
            for name in HEADERS:
                data = (self.root / (name + ".csv")).read_bytes()
                inputs[name] = dict(
                    sha256=hashlib.sha256(data).hexdigest(),
                    bytes=len(data),
                    rows=len(getattr(self, name)),
                )
            expected = dict(
                schema_version=1,
                ok=not evidence,
                policy=dict(
                    features=self.features,
                    max_age_us=None,
                    eligibility="event_at <= prediction_at and known_at <= prediction_at",
                    selection="maximum (event_at, known_at); equal pairs invalid",
                    feature_max_age_us=policies,
                ),
                inputs=inputs,
                requests=8,
                checked_pairs=24,
                expected_missing=absent,
                violations=len(evidence),
                reasons=dict(sorted(reasons.items())),
                by_feature=by_feature,
                examples=evidence[:7],
                examples_omitted=max(0, len(evidence) - 7),
            )
            with self.subTest(case=case):
                self.assertEqual(row, expected)

    def cli(self, raw, extra=()):
        policy = self.root / "policy.json"
        policy.write_bytes(raw)
        out, err = io.StringIO(), io.StringIO()
        argv = (
            [str(p) for p in self.paths()]
            + [
                "--feature",
                "balance",
                "--feature",
                "plan",
                "--temp-dir",
                str(self.scratch),
                "--feature-age-limits",
                str(policy),
            ]
            + list(extra)
        )
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                status = main(argv)
            except SystemExit as exc:
                status = exc.code
        self.assertEqual(list(self.scratch.iterdir()), [])
        return status, out.getvalue(), err.getvalue()

    def test_cli_success_and_violation_and_bom(self):
        code, out, err = self.cli(b'\xef\xbb\xbf{"balance":172800000000,"plan":null}')
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertEqual(
            json.loads(out)["policy"]["feature_max_age_us"],
            {"balance": 2 * DAY, "plan": None},
        )
        code, out, err = self.cli(b'{"balance":0,"plan":null}')
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        self.assertEqual(json.loads(out)["reasons"], {"expired": 1})

    def test_cli_policy_exact_byte_limit_and_published_example(self):
        raw = b'{"balance":null,"plan":null}'
        code, out, err = self.cli(raw + b" " * (1048576 - len(raw)))
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        self.assertTrue(json.loads(out)["ok"])
        example = Path(__file__).resolve().parents[1] / "examples" / "feature-ages"
        for name, expected_code in (("selected.csv", 0), ("stale.csv", 1)):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(
                    [
                        str(example / "history.csv"),
                        str(example / "requests.csv"),
                        str(example / name),
                        "--feature",
                        "balance",
                        "--feature",
                        "plan",
                        "--feature-age-limits",
                        str(example / "ages.json"),
                    ]
                )
            self.assertEqual(code, expected_code)
            self.assertEqual(err.getvalue(), "")
            row = json.loads(out.getvalue())
            self.assertEqual(
                row["reasons"], {} if not expected_code else {"expired": 1}
            )
            self.assertEqual(row["expected_missing"], 1)

    def test_cli_invalid_policy_no_partial_json(self):
        invalid = [
            b"",
            b"null",
            b"[]",
            b"{}",
            b'{"balance":0,"balance":1,"plan":null}',
            b'{"balance":0,"balan\\u0063e":1,"plan":null}',
            b'{"balance":true,"plan":null}',
            b'{"balance":1.0,"plan":null}',
            b'{"balance":NaN,"plan":null}',
            b'{"balance":Infinity,"plan":null}',
            b'{"balance":-1,"plan":null}',
            b'{"balance":null}',
            b"\xff",
            b"{",
            b"{}{}",
            b"[" * 2000,
            b" " * 1048577,
        ]
        for raw in invalid:
            with self.subTest(raw=raw[:120]):
                code, out, err = self.cli(raw)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("asofaudit:", err)
        code, out, err = self.cli(b'{"balance":0,"plan":null}', ["--max-age-us", "0"])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("not allowed", err)

    def test_cli_missing_policy_and_cleanup_after_manifest_failure(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(
                main(
                    ["absent"] * 3
                    + [
                        "--feature",
                        "f",
                        "--feature-age-limits",
                        str(self.root / "missing.json"),
                    ]
                ),
                2,
            )
        self.assertEqual(out.getvalue(), "")
        self.assertIn("invalid feature age policy", err.getvalue())
        self.selections = []
        code, out, err = self.cli(b'{"balance":0,"plan":null}')
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("coverage", err)
