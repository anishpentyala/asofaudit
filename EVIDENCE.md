# Evidence and boundaries

Source pages inspected November 13, 2026. These motivate the problem, not a claim
that this tool implements their complete semantics or outperforms them.

## Feast: two clocks

https://docs.feast.dev/getting-started/concepts/point-in-time-joins

> By default, point-in-time joins only constrain the feature's event timestamp.

The documentation describes created timestamps as a deduplication tie-breaker
unless the opt-in cutoff is enabled, and states:

> This adds a `created_timestamp <= entity_timestamp` condition to the join

asofaudit always applies both declared clocks, and checks the selected immutable
version identifier against a separate manifest. It cannot prove either timestamp
was true, or that a pipeline actually used that selected payload.

## Existing tool: Timefence

https://timefence.dev/api/audit/

> Two modes: 1. Rebuild-and-compare: provide features, keys, label_time. 2. Temporal
> check: provide feature_time_columns.

This project does not claim to invent point-in-time validation. Its narrow input
contract is three explicit CSV manifests with a required selected-version (or
explicit absence) for every request-feature pair. It checks version identity,
late corrections and complete coverage, without rebuilding a feature pipeline or
requiring feature values.

## Local verification

The source tests include a seeded independent integer-day nested-loop oracle:
45 histories, 40 requested pairs each, checking both mismatch totals and every
expected version in evidence, including intentionally incorrect selections.
There are separate controls for an older event with a newer known timestamp,
late corrections, missing/incorrect selections, strict manifest validation,
private temporary storage, actual SQLite-full and read-interruption errors,
cleanup, input preservation, and microsecond UTC boundaries.

These are synthetic local tests, not production usage, external adoption,
Windows/macOS verification, or a proof of leakage-free data.

## Per-feature age policy (November 14, 2026)

The same Feast page was fetched again November 14. Its example places
`ttl=timedelta(hours=2)` on a `FeatureView` and states:

> Feast will scan backward in time from the entity dataframe timestamp up to a maximum of the TTL time specified.

This motivates auditing differing declared ages together. asofaudit's mapping is
per exact caller feature name, not a feature-view importer; no complete Feast
semantic equivalence is claimed. See issue
https://github.com/anishpentyala/asofaudit/issues/3 for the proposed policy before
implementation. Tests independently enumerate eligible versions with each
feature's age and check the complete report and failure behavior.
