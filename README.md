# asofaudit

Check whether a training-data pipeline selected the feature versions that were
actually eligible at each prediction time, including late-arriving corrections.
No feature values, feature-store server, pandas, network access, or input code
execution are needed. Python 3.9+ with the standard-library `sqlite3` module.

This is a **version-selection audit**, not proof that a dataset is leakage-free.
It trusts your version history, identifiers, timestamps, and declared policy.

## A correction from the future

A customer's balance event happened January 1. The original version was known
that day. A correction was written January 10. Selecting the correction for a
January 2 prediction uses a version that was not yet known, even though its event
time is before the prediction. Selecting an older version after a newer eligible
event is another error that checking only `feature_time <= prediction_time` misses.

```sh
python -m pip install .
asofaudit examples/history.csv examples/requests.csv examples/selected.csv \
  --feature balance --examples 5
```

The example exits 1, with two violations: `not_yet_known` for `prediction-1` and
`not_latest` for `prediction-2`. The explicit empty selection for `prediction-3`
is correct because that entity has no eligible history. Replacing `selected.csv`
with `correct.csv` exits 0. This is source installation, not a PyPI release.

## Three explicit CSV manifests

| Input | Required columns |
|---|---|
| History | `version_id,entity_id,feature,event_at,known_at` |
| Requests | `request_id,entity_id,prediction_at` |
| Selections | `request_id,feature,version_id` |

- Headers must contain exactly these columns, in any order, without duplicates.
- UTF-8 or UTF-8 BOM, comma-delimited CSV with Python's strict CSV parser.
  Quoted commas and multiline fields work. Ragged/blank data records are invalid.
  This does not implement a separate complete CSV grammar validator.
- IDs and feature names are exact strings, without trimming or case folding.
  `001` and `1` are different. Required fields cannot be blank/whitespace-only or
  contain NUL. Only selection `version_id` may be empty, meaning no feature value.
  There are no inferred null tokens: `NA` is an ordinary identifier.
- Version IDs are globally unique. Request IDs are unique. Each entity/feature
  `(event_at, known_at)` pair must be unique after UTC normalization. Ambiguous
  ties are invalid, even if they would not affect a requested prediction.
- Supply each desired feature with a repeated `--feature` option. Every request
  must have **exactly one selection for every requested feature**, including an
  empty version for no value. Missing rows are invalid, never silently skipped.
- Unknown selected version IDs, unknown requests, unrequested features, duplicate
  selections, empty request files, and invalid history rows are input errors.
  History may be empty. Extra history features/entities are allowed and validated.

Timestamps must have exactly the form `YYYY-MM-DDTHH:MM:SS[.ffffff](Z|+HH:MM|-HH:MM)`.
Fractions have 1-6 digits. Four-digit years 0001-9999, valid dates, seconds 00-59,
hours 00-23, and explicit offsets are required. No naive times, leap seconds,
24:00:00, timezone names, DST inference, or sub-microsecond rounding. All comparisons
use integer UTC microseconds, including dates before 1970.

## Declared selection policy

For the request's exact entity and feature:

1. Keep versions with both `event_at <= prediction_at` and
   `known_at <= prediction_at`. Equality is eligible.
2. With `--max-age-us N`, also require `prediction_at - event_at <= N`.
   This is an inclusive, nonnegative **event-age** limit in microseconds, not an
   ingestion-age limit. Omit it for no age limit.
3. Select the maximum `(event_at, known_at)` in that order. A newer eligible
   event wins over a more recently learned correction to an older event.
4. If no version is eligible, expect an explicit empty selected version.

This policy is fixed, not inferred from the manifests. If your pipeline uses
strict-before times, global snapshot cutoffs, aggregation windows, deletions,
per-feature TTLs, priorities, or another tie-breaker, this model is not sufficient.
A version whose known time precedes its event time is permitted but still must
pass both eligibility comparisons.

A known selected version that violates the policy produces one reason, in this
precedence: `wrong_entity`, `wrong_feature`, `future_event`, `not_yet_known`,
`expired`, `not_latest`. An empty selection when a value exists is
`missing_selection`. The report lists the expected version only when examples
are requested. A wrong version can violate several rules; reason counts are
mutually exclusive, not a count of every possible defect.

## Reports and CI

```sh
asofaudit history.csv requests.csv selected.csv \
  --feature balance --feature plan --max-age-us 604800000000 > audit.json
```

- Exit **0**: complete audit, every requested pair matches this policy.
- Exit **1**: complete audit, some pairs violate this policy. JSON remains complete.
- Exit **2**: invalid/incomplete inputs, bad options, resource limit, or storage
  error. Error on stderr; **no JSON report** on stdout.

JSON schema version 1 includes counts, per-feature counts, mutually exclusive
reason counts, declared policy, and SHA256/byte/row counts of each input. Digests
bind the bytes actually read. They are not signatures, proof of history
completeness, or an atomic cross-file snapshot. Freeze the three manifests before
auditing; concurrent source edits are outside the guarantee.

Examples default to **0**. Use `--examples N` (0-1000) for bounded evidence in
request-ID order and then supplied feature order. Examples expose request IDs,
feature names, selected versions, and expected versions. Counts also disclose
feature names and dataset sizes. Treat reports as private when appropriate.

```python
from asofaudit import audit

report = audit('history.csv', 'requests.csv', 'selected.csv',
               features=['balance'], examples=0)
assert report['ok']  # Only the stated version-selection policy.
```

## Disk, limits, and privacy

Inputs are streamed into a new temporary SQLite database. There is no extraction,
network, telemetry, input modification, or automatic repair. Identifiers and
timestamps are written to disk in plaintext; feature values are never requested.
`--temp-dir DIR` selects an existing scratch parent. On POSIX, the new directory
is mode 0700 and database 0600. Windows permission equivalence is not claimed.

Normal completion and errors close/remove the database and scratch directory.
Removal is not secure erasure. Forced termination/power loss can leave files;
backups, filesystem snapshots and elevated access can expose them. Cleanup failure
is an error and may mask an earlier error. Choose scratch storage accordingly.

Limits default to 1,000,000 rows **per input**, 256 MiB bytes **per input**, and
1,000,000 request-feature pairs. Configure with `--max-rows`, `--max-bytes`, and
`--max-pairs`. Python's CSV field-size limit also applies. Crossing any limit fails
the whole audit. SQLite cache is advisory 8 MiB; this is not a hard RAM/disk/time
bound. SQLite indexes consume extra disk. Large histories of not-yet-known
versions for one entity/feature can make lookups slow. No runtime bound or
large-scale performance claim is made.

## What this does not establish

The audit cannot prove that source timestamps are true, records are complete,
version IDs bind immutable payloads, or logged selections match the data actually
used by a model. It does not inspect values, aggregation/preprocessing code,
labels, train/test groups, semantic duplicates, model memory, or online serving.
A clean report is only agreement between the three supplied manifests and the
explicit two-clock selection policy.

Feast documents why filtering the created/known timestamp matters in addition to
event time: [point-in-time joins](https://docs.feast.dev/getting-started/concepts/point-in-time-joins).
Tools such as [Timefence](https://timefence.dev/api/audit/) cover timestamp audits
and rebuild-and-compare workflows. asofaudit is a narrower independent check of
**selected version identity and complete request-feature coverage** against a
separate version history. It does not replace those tools or claim new research.

## Develop

```sh
python -m pip install -e . coverage ruff build
python -m unittest discover -s tests -v
coverage run --branch --source=asofaudit -m unittest discover -s tests
coverage report -m
ruff check src tests
ruff format --check src tests
python -m build
```

Tests include an independent integer-day nested-loop oracle, late corrections,
wrong entity/feature and absent selections, exact age boundaries, UTC offsets,
invalid inputs, complete pair coverage, storage errors, cleanup, input-byte
preservation, and POSIX scratch modes. Linux local verification is separate from
hosted CI. No Windows, macOS, deployment, adoption, or real-production-data claims.
