"""Command-line audit. Invalid input never emits a plausible partial report."""

import argparse
import json
import sys

from .core import AuditError, audit


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit selected feature versions against event and known time"
    )
    parser.add_argument("history")
    parser.add_argument("requests")
    parser.add_argument("selections")
    parser.add_argument("--feature", action="append", required=True, dest="features")
    parser.add_argument("--max-age-us", type=int)
    parser.add_argument("--examples", type=int, default=0)
    parser.add_argument("--max-rows", type=int, default=1000000)
    parser.add_argument("--max-bytes", type=int, default=268435456)
    parser.add_argument("--max-pairs", type=int, default=1000000)
    parser.add_argument("--temp-dir")
    args = parser.parse_args(argv)
    try:
        report = audit(**vars(args))
    except AuditError as exc:
        print("asofaudit: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))
    return 0 if report["ok"] else 1
