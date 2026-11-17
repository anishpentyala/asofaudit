"""Independent oracle and boundary tests for opt-in strict event eligibility."""

import contextlib
import csv
import io
import random
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from asofaudit import AuditError, audit
from asofaudit.cli import main


def stamp(us):
    return (
        datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
    ).isoformat()


class StrictEventTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def paths(self, history, requests, selections):
        paths = []
        for name, header, rows in (
            ("h", "version_id,entity_id,feature,event_at,known_at", history),
            ("r", "request_id,entity_id,prediction_at", requests),
            ("s", "request_id,feature,version_id", selections),
        ):
            path = self.root / (name + ".csv")
            with path.open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(header.split(","))
                writer.writerows(rows)
            paths.append(path)
        return paths

    def fixture(self, selected="equal"):
        return self.paths(
            [
                ["older", "e", "f", stamp(9), stamp(10)],
                ["equal", "e", "f", stamp(10), stamp(9)],
            ],
            [["r", "e", stamp(10)]],
            [["r", "f", selected]],
        )

    def test_equal_event_excluded_but_equal_known_included(self):
        paths = self.fixture()
        normal = audit(*paths, features=["f"], examples=1)
        explicit = audit(*paths, features=["f"], examples=1, strict_event_before=False)
        self.assertEqual(normal, explicit)
        self.assertTrue(normal["ok"])
        strict = audit(*paths, features=["f"], examples=1, strict_event_before=True)
        self.assertEqual(strict["reasons"], {"event_at_prediction": 1})
        self.assertEqual(strict["examples"][0]["expected_version"], "older")
        self.assertEqual(
            strict["policy"]["eligibility"],
            "event_at < prediction_at and known_at <= prediction_at",
        )
        self.assertTrue(
            audit(*self.fixture("older"), features=["f"], strict_event_before=True)[
                "ok"
            ]
        )

    def test_inclusive_age_lower_bound_and_zero_age(self):
        paths = self.fixture("older")
        self.assertTrue(
            audit(*paths, features=["f"], strict_event_before=True, max_age_us=1)["ok"]
        )
        expired = audit(
            *paths, features=["f"], strict_event_before=True, max_age_us=0, examples=1
        )
        self.assertEqual(expired["reasons"], {"expired": 1})
        self.assertEqual(expired["examples"][0]["expected_version"], "")
        self.assertEqual(expired["expected_missing"], 1)
        self.assertTrue(
            audit(
                *self.fixture(""),
                features=["f"],
                strict_event_before=True,
                feature_max_age_us={"f": 0},
            )["ok"]
        )

    def test_utc_normalized_equality(self):
        paths = self.paths(
            [["v", "e", "f", "2024-01-01T01:00:00+01:00", "2023-12-31T23:00:00Z"]],
            [["r", "e", "2023-12-31T19:00:00-05:00"]],
            [["r", "f", "v"]],
        )
        self.assertEqual(
            audit(*paths, features=["f"], strict_event_before=True)["reasons"],
            {"event_at_prediction": 1},
        )

    def test_boolean_validation_precedes_input_io(self):
        for value in (None, 0, 1, "false", [], {}):
            with (
                self.subTest(value=value),
                patch("asofaudit.core.sqlite3.connect") as connect,
            ):
                with self.assertRaisesRegex(
                    AuditError, "strict_event_before must be a boolean"
                ):
                    audit(
                        "missing",
                        "missing",
                        "missing",
                        features=["f"],
                        strict_event_before=value,
                    )
                connect.assert_not_called()

    def test_reason_precedence_and_future_event(self):
        history = [
            ["entity", "other", "f", stamp(10), stamp(20)],
            ["feature", "e", "other", stamp(10), stamp(20)],
            ["future", "e", "f", stamp(11), stamp(20)],
            ["equal", "e", "f", stamp(10), stamp(20)],
            ["known", "e", "f", stamp(9), stamp(20)],
        ]
        expected = {
            "entity": "wrong_entity",
            "feature": "wrong_feature",
            "future": "future_event",
            "equal": "event_at_prediction",
            "known": "not_yet_known",
        }
        for selected, reason in expected.items():
            with self.subTest(selected=selected):
                p = self.paths(history, [["r", "e", stamp(10)]], [["r", "f", selected]])
                self.assertEqual(
                    audit(*p, features=["f"], strict_event_before=True)["reasons"],
                    {reason: 1},
                )

    def test_cli_explicit_mode(self):
        args = [str(p) for p in self.fixture()] + [
            "--feature",
            "f",
            "--strict-event-before",
        ]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(args), 1)
        import json

        self.assertEqual(
            json.loads(out.getvalue())["reasons"], {"event_at_prediction": 1}
        )

    def test_seeded_independent_nested_loop_oracle(self):
        rng = random.Random(52911)
        for case in range(150):
            # No SQL, sweep activation, core timestamp parser or reason helper in oracle.
            rows = []
            pairs = set()
            for i in range(rng.randrange(1, 24)):
                e, f, t, k = (
                    rng.choice("ab"),
                    rng.choice("fg"),
                    rng.randrange(-5, 7),
                    rng.randrange(-5, 7),
                )
                if (e, f, t, k) not in pairs:
                    pairs.add((e, f, t, k))
                    rows.append((str(i), e, f, t, k))
            req = [
                ("r" + str(i), rng.choice("ab"), rng.randrange(-5, 7)) for i in range(8)
            ]
            ages = {"f": rng.choice([None, 0, 1, 4]), "g": rng.choice([None, 0, 1, 4])}
            for strict in (False, True):
                selections = []
                expected = {}
                for r, entity, when in req:
                    for feature in ("g", "f"):
                        eligible = [
                            v
                            for v in rows
                            if v[1] == entity
                            and v[2] == feature
                            and (v[3] < when if strict else v[3] <= when)
                            and v[4] <= when
                            and (ages[feature] is None or when - v[3] <= ages[feature])
                        ]
                        version = (
                            max(eligible, key=lambda v: (v[3], v[4]))[0]
                            if eligible
                            else ""
                        )
                        expected[(r, feature)] = version
                        selections.append([r, feature, ""])
                paths = self.paths(
                    [[v, e, f, stamp(t), stamp(k)] for v, e, f, t, k in rows],
                    [[r, e, stamp(t)] for r, e, t in req],
                    selections,
                )
                report = audit(
                    *paths,
                    features=["g", "f"],
                    strict_event_before=strict,
                    feature_max_age_us=ages,
                    examples=1000,
                )
                observed = {
                    (x["request_id"], x["feature"]): x["expected_version"]
                    for x in report["examples"]
                }
                self.assertEqual(
                    observed, {p: v for p, v in expected.items() if v}, (case, strict)
                )
                self.assertEqual(
                    report["expected_missing"], sum(not v for v in expected.values())
                )
                self.assertEqual(
                    report["violations"], sum(bool(v) for v in expected.values())
                )
                paths = self.paths(
                    [[v, e, f, stamp(t), stamp(k)] for v, e, f, t, k in rows],
                    [[r, e, stamp(t)] for r, e, t in req],
                    [[r, f, v] for (r, f), v in expected.items()],
                )
                self.assertTrue(
                    audit(
                        *paths,
                        features=["g", "f"],
                        strict_event_before=strict,
                        feature_max_age_us=ages,
                    )["ok"],
                    (case, strict),
  )
