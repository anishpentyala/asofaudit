"""Command-line audit. Invalid input never emits a plausible partial report."""

import argparse
import json
import sys

from .core import AuditError, audit

_POLICY_BYTES = 1048576


def _duplicate_checked_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("duplicate feature age policy key")
        result[key] = value
    return result


def _reject_constant(value):
    raise AuditError("non-finite numbers are invalid JSON policy values")


def _load_age_limits(path):
    try:
        with open(path, "rb") as stream:
            raw = stream.read(_POLICY_BYTES + 1)
        if len(raw) > _POLICY_BYTES:
            raise AuditError("feature age policy exceeds 1 MiB byte limit")
        return json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=_duplicate_checked_object,
            parse_constant=_reject_constant,
        )
    except (OSError, ValueError, RecursionError) as exc:
        raise AuditError("invalid feature age policy: %s" % exc) from exc


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Audit selected feature versions against event and known time"
    )
    parser.add_argument("history")
    parser.add_argument("requests")
    parser.add_argument("selections")
    parser.add_argument("--feature", action="append", required=True, dest="features")
    ages = parser.add_mutually_exclusive_group()
    ages.add_argument("--max-age-us", type=int)
    ages.add_argument("--feature-age-limits", metavar="JSON_FILE")
    parser.add_argument("--examples", type=int, default=0)
    parser.add_argument("--max-rows", type=int, default=1000000)
    parser.add_argument("--max-bytes", type=int, default=268435456)
    parser.add_argument("--max-pairs", type=int, default=1000000)
    parser.add_argument("--temp-dir")
    args = parser.parse_args(argv)
    try:
        policy_path = args.feature_age_limits
        del args.feature_age_limits
        if policy_path is not None:
            args.feature_max_age_us = _load_age_limits(policy_path)
            if args.feature_max_age_us is None:
                raise AuditError("feature age policy must be a complete JSON object")
        report = audit(**vars(args))
    except AuditError as exc:
        print("asofaudit: %s" % exc, file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2))
    return 0 if report["ok"] else 1
