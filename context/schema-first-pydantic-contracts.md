<!-- context/schema-first-pydantic-contracts.md -->
# Schema-first Pydantic contracts — the two-axis rule (SSOT + trust boundary)

Python translation of the schema-first Zod doctrine. The two axes are unchanged;
only the mechanism differs. **Do not conflate the axes.**

## AXIS 1 — RUNTIME VALIDATION is governed by the TRUST BOUNDARY

Untrusted or external input MUST be validated with Pydantic at the boundary:
config files, environment variables, HTTP responses, CSV/JSON/Parquet headers
from third parties, queue payloads, anything read off disk that another process
wrote.

Trusted internal data already produced and typed by our own code is NOT
re-validated. Re-validating typed internal data is the redundant-validation
anti-pattern. *Validate trust boundaries, type-check everything else.*

**Scale caveat specific to this project:** Pydantic validates ONE object
crossing a boundary — a config, a manifest, a probe result. It must never be
used per-record inside a Spark job. Row-level shape is enforced by an explicit
`StructType` schema on read; that is Spark's boundary mechanism, and Pydantic
per row would serialize the whole dataset through Python.

## AXIS 2 — SHAPE DEFINITION (SSOT) is governed by DUPLICATION

A cross-boundary contract shape, or any shape that would be hand-written more
than once, derives from ONE definition. In Python the model class already *is*
the type, so `z.infer` has no direct equivalent — the rule becomes: never
hand-write a `TypedDict`, dataclass, or protocol that parallels a Pydantic
model. Import the model.

A purely internal, single-use shape crossing no trust boundary and duplicated
nowhere stays a plain annotation, dataclass, or inline `Literal`. Do NOT force
Pydantic onto internal-only, non-duplicated shapes.

## "Zero tolerance" = exactly THREE fix-triggers

1. Trust-boundary input with no Pydantic validation.
2. The same contract shape defined more than once, or hand-written when a model
   exists → import the model.
3. NOT forcing Pydantic onto internal-only, non-duplicated shapes.

## Canonical SSOT vocabulary pattern (copy this)

Zod derives a type and a schema from one `as const` array. Python derives both
from one `Literal` alias:

```python
type SparkVersion = Literal["4.0", "4.1"]  # THE definition
SUPPORTED_SPARK_VERSIONS: Final = get_args(SparkVersion.__value__)  # derived
```

The alias is the single definition. The runtime tuple derives from it, so the
list can never drift from the type. mypy rejects a bad literal at author time
and Pydantic rejects a bad value at runtime — the two-axis guarantee from one
line.

**Gotcha, mirroring Zod's:** on a PEP 695 `type` alias you must read
`.__value__` before `get_args`, or you get `()` and the vocabulary silently
becomes empty. Write it the other way round — tuple first, then
`Literal[*VALUES]` — and it fails, because `Literal` does not accept unpacking.

Use `StrEnum` instead when the vocabulary needs behaviour or stable member
names (see `ExitCode` in `ingest/probe.py`). Use a `Literal` alias when it is a
pure value vocabulary.

## Case study: spark_version (fixed)

**Violation.** `SUPPORTED_SPARK_VERSIONS` was a `frozenset`, checked by a
custom `field_validator`, while the field stayed `spark_version: str`. Nothing
derived from the vocabulary: `ClusterConfig(spark_version="3.5")` type-checked
cleanly and only failed at runtime, and the error message restated the list a
second time.

**Fix.** One `Literal` alias; the field takes the alias, the tuple derives, the
custom validator is deleted. Pydantic's own `literal_error` names the permitted
values, so the prose message was duplication too.

## Explicitly NOT violations — leave as plain annotations

- `data_security_mode`, `SourceConfig.format` — inline `Literal`, single use,
  no duplication.
- `DEFAULT_MEMBER`, `_CHUNK_BYTES`, `_RETRYABLE_STATUS` — internal constants,
  no boundary, no duplication.
- `Opener` / response protocols — internal seams for dependency injection.
- pytest fixture helpers (`_cluster`, `_wdi_headers`) — test-local builders.

## Audit backlog

**P0 (confirmed):**
1. `spark_version` vocabulary — FIXED, above.

**Verified compliant (Axis 1 satisfied at every boundary):**
- `conf/pipeline.yml` → `yaml.safe_load` → `PipelineConfig.model_validate`
- `DATABRICKS_*` env → `DatabricksSettings(BaseSettings)`
- `*.manifest.json` off disk → `IngestManifest.model_validate_json`
- WDI archive headers → `WdiProbeResult` with accounting validators

**P2 (inspect before classifying):** the Databricks environment-version
envelope (Python 3.12.3, JDK 17, Scala 2.13, Spark 4.0) is restated in
`mise.toml`, `README.md`, and `config.py`. Those are prose comments in
different tools, not duplicated code shapes — documentation, not an Axis-2
violation. Only `spark_version` was executable duplication.
