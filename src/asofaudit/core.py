"""Strict CSV manifests and a SQLite-backed bitemporal selection oracle."""

import csv
import hashlib
import heapq
import io
import os
import re
import sqlite3
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone


class AuditError(ValueError):
    """Input is invalid/incomplete or storage could not finish the audit."""


_TIME = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z",
    re.ASCII,
)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_HEADERS = {
    "history": ("version_id", "entity_id", "feature", "event_at", "known_at"),
    "requests": ("request_id", "entity_id", "prediction_at"),
    "selections": ("request_id", "feature", "version_id"),
}


def instant(value):
    """Return UTC integer microseconds, accepting only the documented grammar."""
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise AuditError("timestamp must have ISO date, seconds and explicit offset")
    # Validate clock fields explicitly: newer Python versions accept 24:00:00,
    # while older versions reject it. Keep one grammar across interpreters.
    if int(value[11:13]) > 23 or int(value[14:16]) > 59 or int(value[17:19]) > 59:
        raise AuditError("invalid timestamp clock fields")
    # datetime permits offsets with minute components >=60; reject those aliases.
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise AuditError("invalid timestamp offset")
    try:
        dt = datetime.fromisoformat(
            value[:-1] + "+00:00" if value[-1] == "Z" else value
        )
        delta = dt.astimezone(timezone.utc) - _EPOCH
    except (ValueError, OverflowError) as exc:
        raise AuditError("invalid or out-of-range timestamp") from exc
    return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds


def _integer(value, name, minimum):
    if type(value) is not int or value < minimum:
        raise AuditError("%s must be an integer >= %s" % (name, minimum))


class _DigestReader(io.RawIOBase):
    def __init__(self, source, limit):
        self.source = source
        self.limit = limit
        self.count = 0
        self.digest = hashlib.sha256()

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.source.read(min(len(buffer), self.limit - self.count + 1))
        self.count += len(data)
        if self.count > self.limit:
            raise AuditError("input byte limit exceeded")
        self.digest.update(data)
        buffer[: len(data)] = data
        return len(data)


@contextmanager
def _rows(path, kind, receipts, max_bytes, max_rows):
    try:
        with open(path, "rb") as source:
            digest = _DigestReader(source, max_bytes)
            with io.TextIOWrapper(
                io.BufferedReader(digest), encoding="utf-8-sig", newline=""
            ) as text:
                reader = csv.reader(text, strict=True)
                header = next(reader, None)
                if (
                    header is None
                    or len(header) != len(set(header))
                    or set(header) != set(_HEADERS[kind])
                ):
                    raise AuditError(
                        "%s: expected exactly columns %s"
                        % (kind, ",".join(_HEADERS[kind]))
                    )
                positions = [header.index(name) for name in _HEADERS[kind]]

                def generate():
                    count = 0
                    for row in reader:
                        count += 1
                        if count > max_rows:
                            raise AuditError("%s: row limit exceeded" % kind)
                        if len(row) != len(header):
                            raise AuditError(
                                "%s record %s: ragged or blank record" % (kind, count)
                            )
                        ordered = tuple(row[index] for index in positions)
                        required = ordered[:-1] if kind == "selections" else ordered
                        if any(
                            not value.strip() or "\x00" in value for value in required
                        ):
                            raise AuditError(
                                "%s record %s: blank or NUL-containing field"
                                % (kind, count)
                            )
                        if kind == "selections" and "\x00" in ordered[-1]:
                            raise AuditError("selections: NUL-containing version_id")
                        yield ordered
                    receipts[kind] = {
                        "sha256": digest.digest.hexdigest(),
                        "bytes": digest.count,
                        "rows": count,
                    }

                yield generate()
                if kind not in receipts:
                    raise AuditError("%s: input was not completely consumed" % kind)
    except AuditError:
        raise
    except (OSError, UnicodeError, csv.Error) as exc:
        raise AuditError("%s: %s" % (kind, exc)) from exc


def _reason(selected, expected, db, entity, feature, when, ttl):
    if selected == expected:
        return None
    if not selected:
        return "missing_selection"
    event = db.execute(
        "SELECT entity, feature, event, known FROM history WHERE version=?", (selected,)
    ).fetchone()
    if event[0] != entity:
        return "wrong_entity"
    if event[1] != feature:
        return "wrong_feature"
    if event[2] > when:
        return "future_event"
    if event[3] > when:
        return "not_yet_known"
    if ttl is not None and when - event[2] > ttl:
        return "expired"
    return "not_latest"


class _EarlierEvidence:
    """Reverse key comparison keeps the latest retained example at heap root."""

    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __lt__(self, other):
        return self.key > other.key


def audit(
    history,
    requests,
    selections,
    *,
    features,
    max_age_us=None,
    examples=0,
    max_rows=1000000,
    max_bytes=268435456,
    max_pairs=1000000,
    temp_dir=None,
):
    """Return a complete report, or raise AuditError without a partial report.

    Sources are CSV paths. Features must be an explicit unique sequence of names.
    max_age_us is inclusive event age, not age since ingestion. All limits are per
    input except max_pairs. Scratch contains plaintext identifiers and times.
    """
    try:
        history, requests, selections = [
            os.fspath(path) for path in (history, requests, selections)
        ]
        if temp_dir is not None:
            temp_dir = os.fsdecode(os.fspath(temp_dir))
    except TypeError as exc:
        raise AuditError("input and scratch paths must be filesystem paths") from exc
    if isinstance(features, (str, bytes)):
        raise AuditError("features must be a sequence, not a string")
    try:
        features = tuple(features)
    except TypeError as exc:
        raise AuditError("features must be a sequence") from exc
    if not features or any(
        not isinstance(f, str) or not f.strip() or "\x00" in f for f in features
    ):
        raise AuditError("features must contain nonblank strings")
    if len(set(features)) != len(features):
        raise AuditError("duplicate requested feature")
    for name, value, minimum in (
        ("examples", examples, 0),
        ("max_rows", max_rows, 1),
        ("max_bytes", max_bytes, 1),
        ("max_pairs", max_pairs, 1),
    ):
        _integer(value, name, minimum)
    if examples > 1000:
        raise AuditError("examples must be <= 1000")
    if len(features) > max_pairs:
        raise AuditError("requested feature count exceeds pair limit")
    if max_age_us is not None:
        _integer(max_age_us, "max_age_us", 0)
        if max_age_us > 315537897599999999:
            raise AuditError("max_age_us exceeds supported datetime range")
    receipts = {}
    try:
        with tempfile.TemporaryDirectory(prefix="asofaudit-", dir=temp_dir) as scratch:
            os.chmod(scratch, 0o700)
            filename = os.path.join(scratch, "audit.sqlite3")
            # Pre-create with private permissions before SQLite opens it.
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            db = sqlite3.connect(filename)
            try:
                db.execute("PRAGMA temp_store=MEMORY")
                db.execute("PRAGMA cache_size=-8192")
                db.executescript("""
                    CREATE TABLE history(version TEXT PRIMARY KEY, entity TEXT NOT NULL,
                        feature TEXT NOT NULL, event INTEGER NOT NULL, known INTEGER NOT NULL,
                        eligible INTEGER NOT NULL DEFAULT 0,
                        UNIQUE(entity,feature,event,known));
                    CREATE INDEX lookup ON history(entity,feature,event DESC,known DESC) WHERE eligible=1;
                    CREATE INDEX arrival ON history(known);
                    CREATE TABLE requests(id TEXT PRIMARY KEY, entity TEXT NOT NULL, at INTEGER NOT NULL);
                    CREATE INDEX request_time ON requests(at,id);
                    CREATE TABLE selections(request TEXT NOT NULL, feature TEXT NOT NULL,
                        version TEXT NOT NULL, PRIMARY KEY(request,feature));
                """)
                with _rows(history, "history", receipts, max_bytes, max_rows) as rows:
                    for version, entity, feature, event, known in rows:
                        db.execute(
                            "INSERT INTO history(version,entity,feature,event,known) VALUES(?,?,?,?,?)",
                            (version, entity, feature, instant(event), instant(known)),
                        )
                with _rows(requests, "requests", receipts, max_bytes, max_rows) as rows:
                    count = 0
                    for request, entity, when in rows:
                        count += 1
                        if count * len(features) > max_pairs:
                            raise AuditError("request-feature pair limit exceeded")
                        db.execute(
                            "INSERT INTO requests VALUES(?,?,?)",
                            (request, entity, instant(when)),
                        )
                if not count:
                    raise AuditError("at least one request is required")
                requested = set(features)
                with _rows(
                    selections, "selections", receipts, max_bytes, max_rows
                ) as rows:
                    for request, feature, version in rows:
                        if feature not in requested:
                            raise AuditError("selection has an unrequested feature")
                        if not db.execute(
                            "SELECT 1 FROM requests WHERE id=?", (request,)
                        ).fetchone():
                            raise AuditError("selection has an unknown request")
                        if (
                            version
                            and not db.execute(
                                "SELECT 1 FROM history WHERE version=?", (version,)
                            ).fetchone()
                        ):
                            raise AuditError("selection has an unknown version")
                        db.execute(
                            "INSERT INTO selections VALUES(?,?,?)",
                            (request, feature, version),
                        )
                expected_pairs = count * len(features)
                if receipts["selections"]["rows"] != expected_pairs:
                    raise AuditError(
                        "selection coverage incomplete: expected %s pairs, received %s"
                        % (expected_pairs, receipts["selections"]["rows"])
                    )
                reasons = {}
                evidence = []
                checked = 0
                expected_missing = 0
                by_feature = {
                    feature: {"checked": 0, "violations": 0, "expected_missing": 0}
                    for feature in features
                }
                # Activate each history row at most once. The partial lookup index
                # contains only versions already known at the current request time.
                # Requests are chronological internally; examples retain the public
                # request-ID/feature-order contract through a bounded max heap.
                previous = -9223372036854775808
                for request, entity, when in db.execute(
                    "SELECT id,entity,at FROM requests ORDER BY at,id"
                ):
                    if when != previous:
                        db.execute(
                            "UPDATE history SET eligible=1 WHERE known>? AND known<=?",
                            (previous, when),
                        )
                        previous = when
                    for position, feature in enumerate(features):
                        params = [entity, feature, when, when]
                        query = "SELECT version FROM history WHERE entity=? AND feature=? AND event<=? AND known<=? AND eligible=1"
                        if max_age_us is not None:
                            query += " AND event>=?"
                            params.append(when - max_age_us)
                        query += " ORDER BY event DESC, known DESC LIMIT 1"
                        found = db.execute(query, params).fetchone()
                        expected = found[0] if found else ""
                        selected = db.execute(
                            "SELECT version FROM selections WHERE request=? AND feature=?",
                            (request, feature),
                        ).fetchone()[0]
                        checked += 1
                        by_feature[feature]["checked"] += 1
                        if not expected:
                            expected_missing += 1
                            by_feature[feature]["expected_missing"] += 1
                        reason = _reason(
                            selected, expected, db, entity, feature, when, max_age_us
                        )
                        if reason:
                            reasons[reason] = reasons.get(reason, 0) + 1
                            by_feature[feature]["violations"] += 1
                            if examples:
                                item = _EarlierEvidence(
                                    (request, position),
                                    {
                                        "request_id": request,
                                        "feature": feature,
                                        "selected_version": selected,
                                        "expected_version": expected,
                                        "reason": reason,
                                    },
                                )
                                if len(evidence) < examples:
                                    heapq.heappush(evidence, item)
                                elif item.key < evidence[0].key:
                                    heapq.heapreplace(evidence, item)
                evidence = [
                    item.value for item in sorted(evidence, key=lambda item: item.key)
                ]
                violations = sum(reasons.values())
                report = {
                    "schema_version": 1,
                    "ok": not violations,
                    "policy": {
                        "features": list(features),
                        "max_age_us": max_age_us,
                        "eligibility": "event_at <= prediction_at and known_at <= prediction_at",
                        "selection": "maximum (event_at, known_at); equal pairs invalid",
                    },
                    "inputs": receipts,
                    "requests": count,
                    "checked_pairs": checked,
                    "expected_missing": expected_missing,
                    "violations": violations,
                    "reasons": dict(sorted(reasons.items())),
                    "by_feature": by_feature,
                    "examples": evidence,
                    "examples_omitted": violations - len(evidence),
                }
            finally:
                db.close()
        return report
    except AuditError:
        raise
    except (OSError, sqlite3.Error) as exc:
        raise AuditError("audit storage/input constraint failure: %s" % exc) from exc
