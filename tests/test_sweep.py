"""Internal sweep invariants and public example-order compatibility."""

import contextlib
import csv
import io
import random
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asofaudit import audit
from asofaudit.cli import main


class SweepTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.history = [
            ["early", "e", "f", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"],
            ["late", "e", "f", "2024-01-01T00:00:00Z", "2024-01-03T00:00:00Z"],
            ["second", "e", "g", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"],
            ["ahead", "e", "f", "2024-01-20T00:00:00Z", "2024-01-01T00:00:00Z"],
        ]
        self.requests = [
            ["z", "e", "2024-01-02T00:00:00Z"],
            ["a", "e", "2024-01-04T00:00:00Z"],
            ["m", "e", "2024-01-03T00:00:00Z"],
        ]
        self.selections = [[r[0], f, ""] for r in self.requests for f in ["g", "f"]]

    def paths(self):
        headers = [
            ["version_id", "entity_id", "feature", "event_at", "known_at"],
            ["request_id", "entity_id", "prediction_at"],
            ["request_id", "feature", "version_id"],
        ]
        paths = []
        for i, rows in enumerate([self.history, self.requests, self.selections]):
            path = self.root / ("input%s.csv" % i)
            with path.open("w", newline="") as stream:
                writer = csv.writer(stream)
                writer.writerow(headers[i])
                writer.writerows(rows)
            paths.append(path)
        return paths

    def test_examples_bounded_by_public_order_not_time_order(self):
        for cap in range(8):
            report = audit(
                *self.paths(), features=["g", "f"], examples=cap, temp_dir=self.root
            )
            expected = [
                (request, feature)
                for request in ["a", "m", "z"]
                for feature in ["g", "f"]
            ]
            self.assertEqual(
                [(r["request_id"], r["feature"]) for r in report["examples"]],
                expected[:cap],
            )
            self.assertEqual(report["examples_omitted"], 6 - min(cap, 6))
            versions = {("a", "f"): "late", ("m", "f"): "late", ("z", "f"): "early"}
            for item in report["examples"]:
                self.assertEqual(
                    item["expected_version"],
                    "second"
                    if item["feature"] == "g"
                    else versions[(item["request_id"], item["feature"])],
                )

    def test_same_prediction_time_activates_once(self):
        self.requests = [["r%s" % i, "e", "2024-01-03T00:00:00Z"] for i in range(25)]
        self.selections = [
            [r[0], f, "second" if f == "g" else "late"]
            for r in self.requests
            for f in ["g", "f"]
        ]
        updates = []

        class CountUpdates(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.startswith("UPDATE history SET eligible"):
                    updates.append(tuple(parameters))
                return super().execute(sql, parameters)

        connect = sqlite3.connect
        with patch(
            "asofaudit.core.sqlite3.connect",
            side_effect=lambda p: connect(p, factory=CountUpdates),
        ):
            self.assertTrue(
                audit(*self.paths(), features=["g", "f"], temp_dir=self.root)["ok"]
            )
        self.assertEqual(len(updates), 1)

    def test_activation_failure_cli_no_partial_json_and_cleanup(self):
        class FailActivation(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.startswith("UPDATE history SET eligible"):
                    raise sqlite3.OperationalError("activation failed")
                return super().execute(sql, parameters)

        connect = sqlite3.connect
        args = [str(p) for p in self.paths()] + [
            "--feature",
            "f",
            "--feature",
            "g",
            "--temp-dir",
            str(self.root),
        ]
        before = sorted(p.name for p in self.root.iterdir())
        out, err = io.StringIO(), io.StringIO()
        with (
            patch(
                "asofaudit.core.sqlite3.connect",
                side_effect=lambda p: connect(p, factory=FailActivation),
            ),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(err),
        ):
            self.assertEqual(main(args), 2)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("activation failed", err.getvalue())
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), before)

    def test_indexed_lookup_excludes_future_known_history(self):
        self.history += [
            [
                "late%s" % i,
                "e",
                "f",
                "2024-01-02T00:00:00Z",
                "2025-01-01T00:00:00.%06dZ" % i,
            ]
            for i in range(300)
        ]
        plans = []
        connect = sqlite3.connect

        class InspectPlan(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.startswith("SELECT version FROM history"):
                    plans.extend(
                        super()
                        .execute("EXPLAIN QUERY PLAN " + sql, parameters)
                        .fetchall()
                    )
                    active_future = (
                        super()
                        .execute(
                            "SELECT COUNT(*) FROM history WHERE eligible=1 AND known>?",
                            (parameters[3],),
                        )
                        .fetchone()[0]
                    )
                    if active_future:
                        raise AssertionError("future-known history activated")
                return super().execute(sql, parameters)

        with patch(
            "asofaudit.core.sqlite3.connect",
            side_effect=lambda p: connect(p, factory=InspectPlan),
        ):
            report = audit(
                *self.paths(), features=["g", "f"], examples=6, temp_dir=self.root
            )
        self.assertEqual(report["violations"], 6)
        self.assertTrue(plans)
        self.assertTrue(all("lookup" in str(plan) for plan in plans), plans)

    def test_sweep_handles_minimum_and_maximum_supported_instants(self):
        self.history = [
            ["first", "e", "f", "0001-01-01T00:00:00Z", "0001-01-01T00:00:00Z"],
            [
                "last",
                "e",
                "f",
                "9999-12-31T23:59:59.999999Z",
                "9999-12-31T23:59:59.999999Z",
            ],
        ]
        self.requests = [
            ["a", "e", "9999-12-31T23:59:59.999999Z"],
            ["z", "e", "0001-01-01T00:00:00Z"],
        ]
        self.selections = [["a", "f", "last"], ["z", "f", "first"]]
        self.assertTrue(audit(*self.paths(), features=["f"], temp_dir=self.root)["ok"])

    def test_shuffled_request_ids_bounded_examples(self):
        rng = random.Random(9038)
        self.requests = [
            ["request%03d" % i, "e", "2024-01-%02dT00:00:00Z" % rng.randint(1, 28)]
            for i in range(120)
        ]
        self.selections = [[r[0], f, ""] for r in self.requests for f in ["g", "f"]]
        rng.shuffle(self.requests)
        for cap in [0, 1, 2, 7, 39, 121, 239, 240, 1000]:
            report = audit(
                *self.paths(), features=["g", "f"], examples=cap, temp_dir=self.root
            )
            expected = [
                (r, f) for r in sorted(x[0] for x in self.requests) for f in ["g", "f"]
            ]
            self.assertEqual(
                [(x["request_id"], x["feature"]) for x in report["examples"]],
                expected[:cap],
            )


if __name__ == "__main__":
    unittest.main()
