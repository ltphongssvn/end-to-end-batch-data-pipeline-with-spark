# src/spark_batch_pipeline/config.py
"""Typed, validated configuration for pipelines and Databricks compute.

WHY PYDANTIC AND NOT A DATACLASS: config files cross a trust boundary. A
dataclass documents intent; Pydantic enforces it at parse time. Cluster config
is the highest-leverage place for a mistake on a data platform -- a missing
autotermination field bills for a cluster nobody shut down, and a Spark version
that drifts from the target runtime breaks UDFs at execution time rather than
at deploy time.

WHY SECRETS ARE NOT MODELLED HERE: DatabricksSettings reads credentials from the
environment, never from YAML. That removes the leak at the source instead of
detecting it later -- there is no field a token could be pasted into. The
credential-shaped validators below are defence in depth for the case where
someone adds a field anyway.

Every constraint fails at COMMIT time via the Lefthook pre-commit hook, not at
deploy time on Databricks. Governance runs where the mistake is made.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Annotated, Final, Literal, get_args

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

# Databricks Free Edition -> serverless -> environment version 5.
#
# SCHEMA-FIRST SSOT: the Literal alias is the ONE definition. The runtime tuple
# derives from it, so the permitted list cannot drift from the declared type.
# Previously this was a frozenset checked by a custom validator while the field
# stayed `str` -- nothing derived, so a bad version type-checked cleanly and
# failed only at runtime.
#
# Gotcha: on a PEP 695 `type` alias you must read .__value__ before get_args,
# or the tuple comes back empty and the vocabulary silently vanishes.
type SparkVersion = Literal["4.0", "4.1"]
SUPPORTED_SPARK_VERSIONS: Final[tuple[str, ...]] = get_args(SparkVersion.__value__)

# Databricks secret references look like {{secrets/<scope>/<key>}}. Anything else
# carrying a credential shape is rejected outright.
_SECRET_REFERENCE = re.compile(r"^\{\{secrets/[\w.-]+/[\w.-]+\}\}$")
_CREDENTIAL_SHAPED = re.compile(
    r"""
      dapi[0-9a-f]{32}                        # Databricks personal access token
    | AKIA[0-9A-Z]{16}                        # AWS access key id
    | ASIA[0-9A-Z]{16}                        # AWS temporary access key id
    | ghp_[A-Za-z0-9]{36}                     # GitHub personal access token
    | -----BEGIN[\ A-Z]*PRIVATE\ KEY-----     # PEM private key
    """,
    re.VERBOSE,
)
_SECRETISH_KEY = re.compile(
    r"(token|secret|password|passwd|apikey|api_key|access_key|credential)", re.IGNORECASE
)


class DatabricksSettings(BaseSettings):
    """Credentials, sourced from the environment only.

    SecretStr keeps the value out of repr(), str(), logs, and tracebacks, so a
    token cannot leak through an exception printed in a notebook.
    """

    model_config = SettingsConfigDict(env_prefix="DATABRICKS_", env_file=".env", extra="ignore")

    host: str = ""
    token: SecretStr = SecretStr("")


class ClusterConfig(BaseModel):
    """Databricks compute definition, governed at commit time."""

    model_config = ConfigDict(extra="forbid", frozen=True, validate_default=True)

    spark_version: SparkVersion = Field(description="Spark major.minor, e.g. '4.0'")
    node_type_id: str = Field(min_length=1)
    num_workers: Annotated[int, Field(ge=0, le=8)]
    # Cost guard: a cluster with no autotermination bills until someone notices.
    autotermination_minutes: Annotated[int, Field(ge=5, le=60)]
    data_security_mode: Literal["SINGLE_USER", "USER_ISOLATION"] = "SINGLE_USER"
    spark_conf: dict[str, str] = Field(default_factory=dict)

    @field_validator("spark_conf")
    @classmethod
    def _no_inline_credentials(cls, conf: dict[str, str]) -> dict[str, str]:
        for key, value in conf.items():
            if _CREDENTIAL_SHAPED.search(value):
                raise ValueError(
                    f"spark_conf[{key!r}] contains a credential-shaped literal. "
                    "Use a secret scope reference: {{secrets/<scope>/<key>}}"
                )
            if _SECRETISH_KEY.search(key) and not _SECRET_REFERENCE.match(value):
                raise ValueError(
                    f"spark_conf[{key!r}] looks like a secret but is not a secret "
                    "scope reference. Expected {{secrets/<scope>/<key>}}"
                )
        return conf


class SourceConfig(BaseModel):
    """One upstream dataset landing in the raw layer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    format: Literal["csv", "json", "parquet", "delta"]
    # HttpUrl parses and validates structure; a hand-rolled regex would not.
    url: HttpUrl
    partition_by: list[str] = Field(default_factory=list)

    @field_validator("url")
    @classmethod
    def _no_embedded_credentials(cls, v: HttpUrl) -> HttpUrl:
        if v.username or v.password:
            raise ValueError("source url embeds credentials; use a secret scope")
        return v


class PipelineConfig(BaseModel):
    """Root config: the three lakehouse layers, sources, and compute."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(min_length=1)
    raw_path: str = Field(min_length=1)
    curated_path: str = Field(min_length=1)
    serving_path: str = Field(min_length=1)
    cluster: ClusterConfig
    sources: list[SourceConfig] = Field(min_length=1)

    @model_validator(mode="after")
    def _layers_are_distinct(self) -> PipelineConfig:
        paths = [self.raw_path, self.curated_path, self.serving_path]
        if len(set(paths)) != len(paths):
            raise ValueError(
                "raw, curated, and serving must be distinct paths; overlapping "
                "layers let a curated write silently clobber raw source data"
            )
        return self

    @model_validator(mode="after")
    def _source_names_unique(self) -> PipelineConfig:
        names = [s.name for s in self.sources]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate source names: {sorted(duplicates)}")
        return self


def load_config(path: Path) -> PipelineConfig:
    """Parse and validate a pipeline config file."""
    return PipelineConfig.model_validate(yaml.safe_load(path.read_text()))


def main(argv: list[str] | None = None) -> int:
    """Validate configs named on argv. Entry point for the pre-commit hook."""
    args = argv if argv is not None else sys.argv[1:]
    paths = [Path(a) for a in args] or sorted(Path("conf").glob("*.yml"))
    if not paths:
        print("no config files to validate")
        return 0

    failed = False
    for path in paths:
        try:
            load_config(path)
        except Exception as exc:
            failed = True
            print(f"FAIL {path}\n{exc}\n", file=sys.stderr)
        else:
            print(f"ok   {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
