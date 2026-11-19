"""Output failures must not masquerade as delivered audits or CPython exit120."""

import contextlib
import io
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from asofaudit.cli import main

ROOT = Path(__file__).resolve().parents[1]
ARGS = [
    str(ROOT / "examples" / name)
    for name in ("history.csv", "requests.csv", "correct.csv")
] + ["--feature", "balance"]


class BrokenOutput(io.StringIO):
    def __init__(self, fail_at):
        super().__init__()
        self.fail_at = fail_at

    def write(self, value):
        if self.fail_at == "write":
            raise OSError("synthetic output failure")
        return super().write(value)

    def flush(self):
        if self.fail_at == "flush":
            raise OSError("synthetic flush failure")
        return super().flush()


class OutputFailureTests(unittest.TestCase):
    def test_main_returns_two_for_write_and_flush_failures(self):
        for failure in ("write", "flush"):
            with self.subTest(failure=failure):
                out = BrokenOutput(failure)
                with (
                    contextlib.redirect_stdout(out),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(main(ARGS), 2)
                # main() is usable by callers that own these streams.
                self.assertFalse(out.closed)

    def test_main_handles_a_failing_diagnostic_stream(self):
        for failure in ("write", "flush"):
            with self.subTest(failure=failure):
                err = BrokenOutput(failure)
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(main(["missing-file"] + ARGS[1:]), 2)
                self.assertEqual(out.getvalue(), "")
                self.assertFalse(err.closed)

    def test_main_serializes_completely_before_writing(self):
        out = io.StringIO()
        with (
            patch("asofaudit.cli.json.dumps", side_effect=MemoryError),
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(ARGS), 2)
        self.assertEqual(out.getvalue(), "")

    def command(self, invocation, args):
        if invocation == "module":
            return [sys.executable, "-m", "asofaudit"] + args
        # Read the configured console target, including on an unpatched baseline.
        import re

        target = re.search(
            r'^asofaudit = "([^"]+)"',
            (ROOT / "pyproject.toml").read_text(),
            re.MULTILINE,
        ).group(1)
        module, name = target.split(":")
        code = (
            "import importlib; raise SystemExit(getattr(importlib.import_module(%r), %r)())"
            % (module, name)
        )
        return [sys.executable, "-c", code] + args

    def environment(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        return env

    @unittest.skipUnless(Path("/dev/full").exists(), "requires /dev/full")
    def test_real_full_stdout_audit_and_help(self):
        for invocation in ("module", "entrypoint"):
            for args in (ARGS, ["--help"]):
                with self.subTest(invocation=invocation, args=args):
                    with open("/dev/full", "wb") as output:
                        result = subprocess.run(
                            self.command(invocation, args),
                            stdout=output,
                            stderr=subprocess.PIPE,
                            env=self.environment(),
                            timeout=10,
                        )
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn(b"Exception ignored", result.stderr)
                    self.assertNotIn(b"Traceback", result.stderr)

    @unittest.skipUnless(os.name == "posix", "requires POSIX pipe descriptors")
    def test_real_closed_stdout_pipe_audit_and_help(self):
        for invocation in ("module", "entrypoint"):
            for args in (ARGS, ["--help"]):
                with self.subTest(invocation=invocation, args=args):
                    read, write = os.pipe()
                    os.close(read)
                    try:
                        result = subprocess.run(
                            self.command(invocation, args),
                            stdout=write,
                            stderr=subprocess.PIPE,
                            env=self.environment(),
                            timeout=10,
                        )
                    finally:
                        os.close(write)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertNotIn(b"Exception ignored", result.stderr)
                    self.assertNotIn(b"Traceback", result.stderr)

    @unittest.skipUnless(Path("/dev/full").exists(), "requires /dev/full")
    def test_real_full_stderr_invalid_input_and_usage(self):
        for invocation in ("module", "entrypoint"):
            for args in (["missing-file"] + ARGS[1:], ["--not-an-option"]):
                with self.subTest(invocation=invocation, args=args):
                    with open("/dev/full", "wb") as output:
                        result = subprocess.run(
                            self.command(invocation, args),
                            stdout=subprocess.PIPE,
                            stderr=output,
                            env=self.environment(),
                            timeout=10,
                        )
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, b"")

    def test_success_violation_help_and_usage_controls(self):
        cases = [
            (ARGS, 0),
            (
                [
                    str(ROOT / "examples" / "history.csv"),
                    str(ROOT / "examples" / "requests.csv"),
                    str(ROOT / "examples" / "selected.csv"),
                    "--feature",
                    "balance",
                ],
                1,
            ),
            (["--help"], 0),
            (["--not-an-option"], 2),
        ]
        for invocation in ("module", "entrypoint"):
            for args, expected in cases:
                with self.subTest(invocation=invocation, expected=expected):
                    result = subprocess.run(
                        self.command(invocation, args),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=self.environment(),
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
                    if args == ARGS or expected == 1:
                        self.assertEqual(json.loads(result.stdout)["ok"], expected == 0)
                    elif args == ["--help"]:
                        self.assertIn(b"usage:", result.stdout)
                    else:
                        self.assertEqual(result.stdout, b"")
