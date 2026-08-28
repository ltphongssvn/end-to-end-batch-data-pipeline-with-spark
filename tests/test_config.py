# tests/test_config.py
"""Governance tests: every constraint must actually reject bad input.

A validator that is never exercised by a failing case is decoration, not a
control. Each test here encodes a real platform failure mode and asserts the
config layer refuses it at parse time.
"""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from spark_batch_pipeline.config import (
    SUPPORTED_SPARK_VERSIONS,
    ClusterConfig,
    DatabricksSettings,
    PipelineConfig,
    SourceConfig,
)


# Builders return raw dicts deliberately. These tests push data across the TRUST
# BOUNDARY, so they must enter through model_validate -- the same entrypoint
# conf/pipeline.yml uses -- rather than through __init__. Pydantic documents the
# split: model_validate takes dictionaries, the constructor takes kwargs.
#
# This also resolves a genuine typing conflict rather than papering over it.
# With pydantic-mypy init_typed the synthesized __init__ is strictly typed, so
# `ClusterConfig(**some_dict)` is an arg-type error: unpacking dict[str, object]
# into typed keyword parameters is uncheckable. Silencing that with ignores
# would have disabled the signal permanently, and the signal is the whole point
# of turning init_typed on. model_validate accepts Any by design, because
# validating unknown input is exactly its job.
def _cluster(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "spark_version": "4.0",
        "node_type_id": "Standard_DS3_v2",
        "num_workers": 2,
        "autotermination_minutes": 20,
    }
    return base | overrides


def _pipeline(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "name": "test",
        "raw_path": "/datalake/raw",
        "curated_path": "/datalake/curated",
        "serving_path": "/datalake/serving",
        "cluster": _cluster(),
        "sources": [{"name": "wdi", "format": "csv", "url": "https://example.com/a.zip"}],
    }
    return base | overrides


def test_valid_cluster_parses() -> None:
    assert ClusterConfig.model_validate(_cluster()).spark_version == "4.0"


def test_unsupported_spark_version_rejected() -> None:
    """Drift from the Databricks target breaks UDFs at execution time.

    Asserts the error TYPE and location, not prose. spark_version derives from
    one Literal alias, so Pydantic enumerates the permitted values itself.
    Matching a hand-written sentence would be a second copy of the vocabulary
    and would break the moment the alias gains a version.
    """
    with pytest.raises(ValidationError) as caught:
        ClusterConfig.model_validate(_cluster(spark_version="3.5"))

    error = caught.value.errors()[0]
    assert error["type"] == "literal_error"
    assert error["loc"] == ("spark_version",)


def test_permitted_versions_derive_from_the_alias() -> None:
    """The runtime tuple must come FROM the type, never be restated beside it.

    An empty tuple here means the PEP 695 `.__value__` gotcha bit us and the
    vocabulary silently vanished, which would let any string through.
    """
    assert SUPPORTED_SPARK_VERSIONS == ("4.0", "4.1")
    for version in SUPPORTED_SPARK_VERSIONS:
        assert (
            ClusterConfig.model_validate(_cluster(spark_version=version)).spark_version == version
        )


def test_missing_autotermination_rejected() -> None:
    """A cluster with no autotermination bills until someone notices."""
    conf = _cluster()
    del conf["autotermination_minutes"]
    with pytest.raises(ValidationError):
        ClusterConfig.model_validate(conf)


@pytest.mark.parametrize("minutes", [0, 4, 61, 1440])
def test_autotermination_outside_bounds_rejected(minutes: int) -> None:
    with pytest.raises(ValidationError):
        ClusterConfig.model_validate(_cluster(autotermination_minutes=minutes))


def test_worker_count_ceiling_enforced() -> None:
    """Free Edition has no capacity for a 64-node cluster; fail before billing."""
    with pytest.raises(ValidationError):
        ClusterConfig.model_validate(_cluster(num_workers=64))


def test_typo_in_field_name_rejected() -> None:
    """extra='forbid' turns a silent no-op typo into a loud failure."""
    with pytest.raises(ValidationError):
        ClusterConfig.model_validate(_cluster(autotermination_minute=20))


# Synthetic credentials are ASSEMBLED, never written as literals.
#
# A literal like "dapi<32 hex>" here is a genuine scanner finding: betterleaks
# cannot tell a fixture from a live token, and it is right not to guess.
# Suppressing it costs an allowlist entry, and a line-numbered fingerprint
# breaks on every edit above it -- a permanent maintenance tax on a value that
# was never secret. Worse, an allowlist entry is a hole a real secret can hide
# in later.
#
# Concatenation removes the finding at its source instead of suppressing it: no
# credential-shaped string exists in the source text, while the runtime value is
# byte-identical, so the validators are exercised exactly as before.
FAKE_DATABRICKS_TOKEN = "dapi" + "0123456789abcdef" * 2
FAKE_AWS_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GITHUB_PAT = "ghp_" + "a" * 36


@pytest.mark.parametrize(
    "token",
    [FAKE_DATABRICKS_TOKEN, FAKE_AWS_KEY_ID, FAKE_GITHUB_PAT],
)
def test_credential_shaped_value_in_spark_conf_rejected(token: str) -> None:
    with pytest.raises(ValidationError, match="credential-shaped"):
        ClusterConfig.model_validate(_cluster(spark_conf={"fs.azure.account.key": token}))


def test_secretish_key_must_use_secret_scope_reference() -> None:
    with pytest.raises(ValidationError, match="secret scope reference"):
        ClusterConfig.model_validate(_cluster(spark_conf={"my.api_key": "plaintext-value"}))


def test_secret_scope_reference_is_accepted() -> None:
    conf = ClusterConfig.model_validate(_cluster(spark_conf={"my.token": "{{secrets/kv/tok}}"}))
    assert conf.spark_conf["my.token"] == "{{secrets/kv/tok}}"


def test_url_with_embedded_credentials_rejected() -> None:
    with pytest.raises(ValidationError, match="embeds credentials"):
        SourceConfig.model_validate(
            {"name": "x", "format": "csv", "url": "https://user:pw@example.com/a.csv"}
        )


def test_non_url_source_rejected() -> None:
    with pytest.raises(ValidationError):
        SourceConfig.model_validate({"name": "x", "format": "csv", "url": "not-a-url"})


def test_overlapping_layers_rejected() -> None:
    """A curated write into the raw path silently destroys source data."""
    with pytest.raises(ValidationError, match="distinct paths"):
        PipelineConfig.model_validate(_pipeline(curated_path="/datalake/raw"))


def test_duplicate_source_names_rejected() -> None:
    dupes = [
        {"name": "wdi", "format": "csv", "url": "https://example.com/a.zip"},
        {"name": "wdi", "format": "json", "url": "https://example.com/b.json"},
    ]
    with pytest.raises(ValidationError, match="duplicate source names"):
        PipelineConfig.model_validate(_pipeline(sources=dupes))


def test_empty_sources_rejected() -> None:
    with pytest.raises(ValidationError):
        PipelineConfig.model_validate(_pipeline(sources=[]))


def test_config_is_frozen() -> None:
    """Immutability stops a notebook mutating cluster config mid-run."""
    cluster = ClusterConfig.model_validate(_cluster())
    with pytest.raises(ValidationError):
        # The frozen model makes this a static error too; the assignment is the
        # point of the test, so the violation is declared rather than silenced
        # project-wide.
        cluster.num_workers = 5  # type: ignore[misc]


def test_token_is_not_exposed_in_repr() -> None:
    """SecretStr keeps credentials out of logs, reprs, and tracebacks."""
    settings = DatabricksSettings(
        host="https://example.databricks.com", token=SecretStr(FAKE_DATABRICKS_TOKEN)
    )
    assert FAKE_DATABRICKS_TOKEN not in repr(settings)
    assert FAKE_DATABRICKS_TOKEN not in str(settings)
    assert settings.token.get_secret_value() == FAKE_DATABRICKS_TOKEN
