# src/spark_batch_pipeline/session.py
"""Single definition of the local SparkSession contract.

Tests and local pipeline runs import from here rather than each building their
own session. Duplicated builders are how a suite passes locally and the job
fails in production: one place sets UTC, the other does not.

Delta JARs: `pip install delta-spark` provides only the Python API. The JVM
side must be fetched from Maven. configure_spark_with_delta_pip derives the
coordinate (io.delta:delta-spark_2.13:<version>) from the INSTALLED pip
version, so the JAR and the Python package cannot drift apart. Hardcoding
"io.delta:delta-spark_2.13:4.0.1" would silently desync on the next uv upgrade.

Note: configure_spark_with_delta_pip OVERWRITES spark.jars.packages. Additional
JARs must be passed via its extra_packages kwarg, never via .config().

On Databricks, Delta and the session already exist; this module is local-only.
"""

from __future__ import annotations

from delta import configure_spark_with_delta_pip
from pyspark.sql import SparkSession

# Determinism settings, not performance settings:
#   shuffle.partitions=1  stable row ordering; assertions cannot flake on
#                         partition boundaries
#   session.timeZone=UTC  Databricks runs UTC; a local America/Los_Angeles
#                         session shifts every timestamp
#   ui.enabled=false      no port binding, so parallel runs cannot collide
_DETERMINISM_CONF: dict[str, str] = {
    "spark.sql.shuffle.partitions": "1",
    "spark.sql.session.timeZone": "UTC",
    "spark.ui.enabled": "false",
}

_DELTA_CONF: dict[str, str] = {
    "spark.sql.extensions": "io.delta.sql.DeltaSparkSessionExtension",
    "spark.sql.catalog.spark_catalog": "org.apache.spark.sql.delta.catalog.DeltaCatalog",
}


def build_local_session(
    app_name: str = "spark-batch-pipeline",
    master: str = "local[2]",
    extra_packages: list[str] | None = None,
) -> SparkSession:
    """Build a local SparkSession with Delta Lake enabled."""
    builder = SparkSession.builder.master(master).appName(app_name)
    for key, value in {**_DETERMINISM_CONF, **_DELTA_CONF}.items():
        builder = builder.config(key, value)
    return configure_spark_with_delta_pip(
        builder, extra_packages=extra_packages or []
    ).getOrCreate()
