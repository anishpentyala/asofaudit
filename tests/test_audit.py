import contextlib
import csv
import hashlib
import io
import json
import os
import random
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from asofaudit import AuditError, audit
from asofaudit.cli import main
from asofaudit.core import instant

HEADERS = {
    "history": ["version_id", "entity_id", "feature", "event_at", "known_at"],
    "requests": ["request_id", "entity_id", "prediction_at"],
    "selections": ["request_id", "feature", "version_id"],
}


def t(day):
    return "2024-01-%02dT00:00:00Z" % day


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.scratch = self.root / "scratch"
        self.scratch.mkdir()
        self.history = [
            ["old", "a", "f", t(1), t(1)],
            ["new", "a", "f", t(2), t(2)],
            ["backfill", "a", "f", t(2), t(4)],
            ["future", "a", "f", t(5), t(1)],
            ["other", "b", "f", t(1), t(1)],
            ["feature2", "a", "g", t(1), t(1)],
        ]
        self.requests = [["r", "a", t(3)]]
        self.selections = [["r", "f", "new"]]

    def write(self, name, rows, header=None):
        path = self.root / (name + ".csv")
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream, quoting=csv.QUOTE_ALL)
            writer.writerow(HEADERS[name] if header is None else header)
            writer.writerows(rows)
        return path

    def paths(self):
        return [self.write(name, getattr(self, name)) for name in HEADERS]

    def run_audit(self, **options):
        opts = {"features": ["f"], "temp_dir": self.scratch}
        opts.update(options)
        report = audit(*self.paths(), **opts)
        self.assertEqual(list(self.scratch.iterdir()), [])
        return report

    def test_correct_and_receipts(self):
        report = self.run_audit()
        self.assertTrue(report["ok"])
        self.assertEqual(report["checked_pairs"], 1)
        self.assertEqual(report["examples"], [])
        for name in HEADERS:
            data = (self.root / (name + ".csv")).read_bytes()
            self.assertEqual(
                report["inputs"][name]["sha256"], hashlib.sha256(data).hexdigest()
            )
            self.assertEqual(report["inputs"][name]["bytes"], len(data))

    def test_mis_selections(self):
        for version, reason in [
            ("old", "not_latest"),
            ("backfill", "not_yet_known"),
            ("future", "future_event"),
            ("other", "wrong_entity"),
            ("feature2", "wrong_feature"),
            ("", "missing_selection"),
        ]:
            with self.subTest(version=version):
                self.selections = [["r", "f", version]]
                report = self.run_audit(examples=1)
                self.assertFalse(report["ok"])
                self.assertEqual(report["reasons"], {reason: 1})
                self.assertEqual(report["examples"][0]["expected_version"], "new")

    def test_late_correction_becomes_eligible(self):
        self.requests[0][-1] = t(4)
        self.selections[0][-1] = "backfill"
        self.assertTrue(self.run_audit()["ok"])

    def test_event_time_primary_not_known_time(self):
        self.history.append(["older-late", "a", "f", t(1), t(3)])
        self.assertTrue(self.run_audit()["ok"])

    def test_equality_is_eligible(self):
        self.requests[0][-1] = t(2)
        self.assertTrue(self.run_audit()["ok"])

    def test_missing_history_explicit_null(self):
        self.history = []
        self.selections[0][-1] = ""
        report = self.run_audit()
        self.assertTrue(report["ok"])
        self.assertEqual(report["expected_missing"], 1)

    def test_future_history_only(self):
        self.history = [self.history[3]]
        self.selections[0][-1] = ""
        self.assertTrue(self.run_audit()["ok"])

    def test_ttl_inclusive_and_expired(self):
        age = 86400 * 1000000
        self.assertTrue(self.run_audit(max_age_us=age)["ok"])
        report = self.run_audit(max_age_us=age - 1, examples=1)
        self.assertEqual(report["reasons"], {"expired": 1})
        self.assertEqual(report["examples"][0]["expected_version"], "")

    def test_zero_age(self):
        self.requests[0][-1] = t(2)
        self.assertTrue(self.run_audit(max_age_us=0)["ok"])

    def test_identity_is_exact(self):
        self.history.append(["zero", "001", "f", t(1), t(1)])
        self.requests[0][1] = "1"
        self.selections[0][-1] = ""
        self.assertTrue(self.run_audit()["ok"])

    def test_multiline_identifiers(self):
        self.history[1][0] = 'new\n,"quoted"'
        self.selections[0][-1] = self.history[1][0]
        self.assertTrue(self.run_audit()["ok"])

    def test_sql_identifiers_are_values(self):
        self.history[1][1] = "a'); DROP TABLE history; --"
        self.requests[0][1] = self.history[1][1]
        self.assertTrue(self.run_audit()["ok"])

    def test_multi_features_complete(self):
        self.selections.append(["r", "g", "feature2"])
        report = self.run_audit(features=["f", "g"])
        self.assertEqual(report["checked_pairs"], 2)
        self.assertEqual(report["by_feature"]["g"]["checked"], 1)

    def test_coverage_and_references(self):
        invalid = [
            [],
            [["unknown", "f", "new"]],
            [["r", "unknown", "new"]],
            [["r", "f", "unknown"]],
            [["r", "f", "new"], ["r", "f", "new"]],
        ]
        for selections in invalid:
            with self.subTest(selections=selections):
                self.selections = selections
                with self.assertRaises(AuditError):
                    self.run_audit()
                self.assertEqual(list(self.scratch.iterdir()), [])

    def test_missing_feature_pair(self):
        with self.assertRaisesRegex(AuditError, "coverage"):
            self.run_audit(features=["f", "g"])

    def test_duplicate_source_id(self):
        self.history.append(["new", "c", "f", t(1), t(1)])
        with self.assertRaises(AuditError):
            self.run_audit()

    def test_ambiguous_source_tie(self):
        self.history.append(["tie", "a", "f", t(2), t(2)])
        with self.assertRaises(AuditError):
            self.run_audit()

    def test_duplicate_requests(self):
        self.requests.append(self.requests[0])
        with self.assertRaises(AuditError):
            self.run_audit()

    def test_empty_requests_invalid(self):
        self.requests = []
        self.selections = []
        with self.assertRaises(AuditError):
            self.run_audit()

    def test_row_and_byte_and_pair_limits(self):
        for options in [
            {"max_rows": 1},
            {"max_bytes": 5},
            {"max_pairs": 1, "features": ["f", "g"]},
        ]:
            with self.subTest(options=options):
                with self.assertRaises(AuditError):
                    self.run_audit(**options)
        self.requests.append(["s", "a", t(3)])
        with self.assertRaisesRegex(AuditError, "pair limit"):
            self.run_audit(max_pairs=1)

    def test_limit_exact_bytes(self):
        paths = self.paths()
        size = max(path.stat().st_size for path in paths)
        self.assertTrue(self.run_audit(max_bytes=size)["ok"])

    def test_validation_options(self):
        for options in [
            {"features": []},
            {"features": "f"},
            {"features": None},
            {"features": ["f", "f"]},
            {"features": [None]},
            {"features": [" "]},
            {"examples": 1001},
            {"examples": True},
            {"max_bytes": 0},
            {"max_rows": -1},
            {"max_pairs": 1.0},
            {"max_age_us": -1},
            {"max_age_us": True},
            {"max_age_us": 10**30},
        ]:
            with self.subTest(options=options):
                with self.assertRaises(AuditError):
                    self.run_audit(**options)

    def test_examples_bound_and_order(self):
        self.requests = [["z", "a", t(3)], ["a", "a", t(3)]]
        self.selections = [["z", "f", "old"], ["a", "f", "old"]]
        report = self.run_audit(examples=1)
        self.assertEqual(report["violations"], 2)
        self.assertEqual(report["examples_omitted"], 1)
        self.assertEqual(report["examples"][0]["request_id"], "a")
        self.assertNotIn("old", json.dumps(self.run_audit()))

    def test_headers_strict_and_reorder(self):
        paths = self.paths()
        data = paths[0].read_text()
        for bad in [
            "version_id,version_id,feature,event_at,known_at\n",
            "version_id\n",
            "",
            data + "\n",
        ]:
            with self.subTest(bad=bad):
                paths[0].write_text(bad)
                with self.assertRaises(AuditError):
                    audit(*paths, features=["f"], temp_dir=self.scratch)
        self.write(
            "history",
            [list(reversed(row)) for row in self.history],
            list(reversed(HEADERS["history"])),
        )
        self.assertTrue(audit(*paths, features=["f"], temp_dir=self.scratch)["ok"])

    def test_bad_data(self):
        paths = self.paths()
        for data in [
            b"\xff",
            b'version_id,entity_id,feature,event_at,known_at\n"unclosed',
            b"version_id,entity_id,feature,event_at,known_at\nshort,row\n",
        ]:
            paths[0].write_bytes(data)
            with self.assertRaises(AuditError):
                audit(*paths, features=["f"], temp_dir=self.scratch)

    def test_blank_and_nul_fields(self):
        for field in range(5):
            old = self.history[0][field]
            for value in ["", "   "]:
                self.history[0][field] = value
                with self.assertRaises(AuditError):
                    self.run_audit()
            self.history[0][field] = old

    def test_nul_input(self):
        paths = self.paths()
        for index in (0, 2):
            before = paths[index].read_bytes()
            needle = b'"old"' if index == 0 else b'"new"'
            paths[index].write_bytes(before.replace(needle, b'"a\x00b"'))
            with self.assertRaises(AuditError):
                audit(*paths, features=["f"], temp_dir=self.scratch)
            paths[index].write_bytes(before)

    def test_bom(self):
        paths = self.paths()
        for path in paths:
            path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
        self.assertTrue(audit(*paths, features=["f"], temp_dir=self.scratch)["ok"])

    def test_missing_input_and_temp_directory(self):
        paths = self.paths()
        with self.assertRaises(AuditError):
            audit(
                self.root / "missing", *paths[1:], features=["f"], temp_dir=self.scratch
            )
        with self.assertRaises(AuditError):
            self.run_audit(temp_dir=self.root / "missing")

    def test_sqlite_error_fails_closed_cleanup(self):
        with patch(
            "asofaudit.core.sqlite3.connect",
            side_effect=sqlite3.OperationalError("disk full"),
        ):
            with self.assertRaisesRegex(AuditError, "disk full"):
                self.run_audit()
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_private_permissions_and_input_preservation(self):
        paths = self.paths()
        before = [p.read_bytes() for p in paths]
        connect = sqlite3.connect
        seen = []

        def checked(filename):
            seen.append(filename)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(os.stat(filename).st_mode), 0o600)
                self.assertEqual(
                    stat.S_IMODE(os.stat(os.path.dirname(filename)).st_mode), 0o700
                )
            return connect(filename)

        with patch("asofaudit.core.sqlite3.connect", side_effect=checked):
            self.assertTrue(audit(*paths, features=["f"], temp_dir=self.scratch)["ok"])
        self.assertEqual(len(seen), 1)
        self.assertEqual([p.read_bytes() for p in paths], before)
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_cli_complete_and_invalid(self):
        paths = self.paths()
        args = [str(p) for p in paths] + [
            "--feature",
            "f",
            "--temp-dir",
            str(self.scratch),
        ]
        for version, code in [("new", 0), ("old", 1), ("unknown", 2)]:
            self.selections[0][-1] = version
            self.paths()
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(main(args), code)
            if code == 2:
                self.assertEqual(out.getvalue(), "")
                self.assertIn("unknown version", err.getvalue())
            else:
                self.assertEqual(json.loads(out.getvalue())["ok"], code == 0)
                self.assertEqual(err.getvalue(), "")

    def test_default_scratch_success_and_cleanup(self):
        # Exercise the public default temp_dir=None path. Use a private process
        # temp root to inspect actual default allocation without shared /tmp races.
        paths = self.paths()
        with patch("asofaudit.core.tempfile.tempdir", str(self.scratch)):
            report = audit(*paths, features=["f"])
        self.assertTrue(report["ok"])
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_invalid_path_types(self):
        paths = self.paths()
        for invalid in (None, 1, True, []):
            with self.subTest(invalid=invalid), self.assertRaises(AuditError):
                audit(invalid, *paths[1:], features=["f"])
        with self.assertRaises(AuditError):
            self.run_audit(temp_dir=1)

    def test_real_sqlite_full_is_invalid(self):
        class FullConnection(sqlite3.Connection):
            def executescript(self, sql):
                result = super().executescript(sql)
                pages = self.execute("PRAGMA page_count").fetchone()[0]
                self.execute("PRAGMA max_page_count=" + str(pages + 2))
                return result

        connect = sqlite3.connect
        self.history = [
            ["v" + str(i), "entity" + str(i) + "x" * 200, "f", t(1), t(1)]
            for i in range(500)
        ]
        with patch(
            "asofaudit.core.sqlite3.connect",
            side_effect=lambda p: connect(p, factory=FullConnection),
        ):
            with self.assertRaisesRegex(AuditError, "full"):
                self.run_audit()
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_database_read_interrupted(self):
        class ReadError(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.startswith("SELECT version FROM history"):
                    raise sqlite3.OperationalError("interrupted lookup")
                return super().execute(sql, parameters)

        connect = sqlite3.connect
        with patch(
            "asofaudit.core.sqlite3.connect",
            side_effect=lambda p: connect(p, factory=ReadError),
        ):
            with self.assertRaisesRegex(AuditError, "interrupted lookup"):
                self.run_audit()
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_base_exception_cleanup(self):
        class Interrupted(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                if sql.startswith("INSERT INTO history"):
                    raise KeyboardInterrupt("stopped")
                return super().execute(sql, parameters)

        connect = sqlite3.connect
        with patch(
            "asofaudit.core.sqlite3.connect",
            side_effect=lambda p: connect(p, factory=Interrupted),
        ):
            with self.assertRaises(KeyboardInterrupt):
                self.run_audit()
        self.assertEqual(list(self.scratch.iterdir()), [])

    def test_offset_normalized_tie_rejected(self):
        self.history.append(["tie", "a", "f", "2024-01-02T01:00:00+01:00", t(2)])
        with self.assertRaises(AuditError):
            self.run_audit()

    def test_microsecond_selection_boundary(self):
        self.history = [
            ["v", "a", "f", "1969-12-31T23:59:59.999999Z", "1970-01-01T00:00:00Z"]
        ]
        self.requests = [["r", "a", "1970-01-01T00:00:00Z"]]
        self.selections = [["r", "f", "v"]]
        self.assertTrue(self.run_audit(max_age_us=1)["ok"])
        self.assertEqual(self.run_audit(max_age_us=0)["reasons"], {"expired": 1})

    def test_seeded_independent_oracle(self):
        rng = random.Random(5801)
        # Use integer days in this oracle, never implementation timestamp parsing
        # or its SQL selection query. All request-feature pairs are fully emitted.
        for case in range(45):
            versions = []
            seen = set()
            for i in range(60):
                entity, feature = rng.choice(["a", "b", "001"]), rng.choice(["f", "g"])
                event, known = rng.randint(1, 15), rng.randint(1, 15)
                if (entity, feature, event, known) in seen:
                    continue
                seen.add((entity, feature, event, known))
                versions.append(("v%s" % i, entity, feature, event, known))
            reqs = [
                (
                    "r%02d" % i,
                    rng.choice(["a", "b", "001", "absent"]),
                    rng.randint(1, 20),
                )
                for i in range(20)
            ]
            ttl_days = rng.choice([None, 0, 2, 10])
            chosen = []
            expected_by_pair = {}
            wrong = 0
            for req, entity, when in reqs:
                for feature in ["f", "g"]:
                    candidates = [
                        v
                        for v in versions
                        if v[1] == entity
                        and v[2] == feature
                        and v[3] <= when
                        and v[4] <= when
                        and (ttl_days is None or when - v[3] <= ttl_days)
                    ]
                    expected = (
                        max(candidates, key=lambda v: (v[3], v[4]))[0]
                        if candidates
                        else ""
                    )
                    selected = (
                        rng.choice(versions)[0] if rng.random() < 0.25 else expected
                    )
                    if selected != expected:
                        expected_by_pair[(req, feature)] = expected
                    wrong += selected != expected
                    chosen.append([req, feature, selected])
            self.history = [[v, e, f, t(ev), t(kn)] for v, e, f, ev, kn in versions]
            self.requests = [[r, e, t(when)] for r, e, when in reqs]
            self.selections = chosen
            rng.shuffle(self.history)
            rng.shuffle(self.requests)
            rng.shuffle(self.selections)
            report = self.run_audit(
                features=["f", "g"],
                examples=1000,
                max_age_us=None if ttl_days is None else ttl_days * 86400 * 1000000,
            )
            actual_by_pair = {
                (entry["request_id"], entry["feature"]): entry["expected_version"]
                for entry in report["examples"]
            }
            self.assertEqual(actual_by_pair, expected_by_pair, case)
            self.assertEqual(report["violations"], wrong, case)
            self.assertEqual(report["checked_pairs"], 40)
            self.assertEqual(report["ok"], wrong == 0)


class TimestampTests(unittest.TestCase):
    def test_offsets_and_microseconds(self):
        self.assertEqual(instant("1970-01-01T00:00:00Z"), 0)
        self.assertEqual(instant("1970-01-01T00:00:00.000001Z"), 1)
        self.assertEqual(instant("1969-12-31T23:59:59.999999Z"), -1)
        self.assertEqual(instant("2024-01-01T01:30:00+01:30"), instant(t(1)))
        self.assertEqual(instant("2023-12-31T16:00:00-08:00"), instant(t(1)))
        self.assertEqual(
            instant("2024-02-29T00:00:00Z") - instant("2024-02-28T00:00:00Z"),
            86400 * 1000000,
        )

    def test_reject_ambiguous_and_invalid(self):
        values = [
            "2024-01-01",
            "2024-01-01T00:00:00",
            "2024-01-01 00:00:00Z",
            "2024-01-01T00:00Z",
            "20240101T000000Z",
            "2024-01-01T00:00:00z",
            "2024-01-01T00:00:00.1234567Z",
            "2024-01-01T00:00:60Z",
            "2024-02-30T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:00:00+00:60",
            "2024-01-01T00:00:00+24:00",
            "0001-01-01T00:00:00+01:00",
            "9999-12-31T23:59:59-01:00",
            " 2024-01-01T00:00:00Z",
            None,
        ]
        for value in values:
            with self.subTest(value=value):
                with self.assertRaises(AuditError):
                    instant(value)


if __name__ == "__main__":
    unittest.main()
