# tests/test_environment.py
"""Environment contract tests.

Regression guard for the drift that motivated this toolchain. If Python or the
JDK is upgraded without updating the Databricks target, these fail loudly here
instead of silently at UDF execution time on serverless.

Target: Databricks Free Edition -> serverless -> environment version 5
        Python 3.12.3 | JDK 17 | Scala 2.13.16 | Spark 4.0.x

CONNECT-SAFETY: tests here avoid SparkContext and _jvm where possible. Those are
Spark Classic internals with no equivalent in Spark Connect, which is what
Databricks serverless runs. Tests that genuinely need Classic carry the
`local_spark` marker so the coupling is explicit and greppable rather than
discovered when the fixture is repointed at Databricks Connect.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from pyspark.sql import SparkSession


def test_python_minor_matches_databricks_serverless_env5() -> None:
    """Spark Connect requires identical client/server Python MINOR versions."""
    assert sys.version_info[:2] == (3, 12), (
        f"Python {sys.version_info.major}.{sys.version_info.minor} != 3.12; "
        "Python UDFs will fail on Databricks serverless."
    )


def test_java_home_is_jdk_17() -> None:
    """Assert the JDK contract via JAVA_HOME rather than Spark internals.

    This is the same JVM Spark launches, but the check uses only public surfaces,
    so it stays valid under both Spark Classic and Spark Connect.
    """
    java_home = os.environ.get("JAVA_HOME")
    assert java_home, "JAVA_HOME is unset; mise activation did not apply"

    java_bin = Path(java_home) / "bin" / "java"
    assert java_bin.is_file(), f"No java executable at {java_bin}"

    # `java -version` writes to stderr by long-standing convention.
    result = subprocess.run([str(java_bin), "-version"], capture_output=True, text=True, check=True)
    banner = result.stderr
    assert '"17.' in banner, f"Expected JDK 17, got: {banner.splitlines()[0]}"
    assert "Temurin" in banner, f"Expected a Temurin build, got: {banner.splitlines()[1]}"

    # Version alone is not enough. CI runners ship their own Temurin 17 and
    # export JAVA_HOME pointing at it, so a version-only assertion passes on a
    # JDK that mise never installed and mise.lock never verified. Asserting the
    # PATH proves the JVM Spark launches is the pinned, checksummed one.
    resolved = Path(java_home).resolve()
    assert "mise" in resolved.parts, (
        f"JAVA_HOME is not mise-managed: {resolved}. "
        "PySpark locates the JVM via JAVA_HOME, so Spark would run on an "
        "unpinned JDK regardless of what `java -version` reports on PATH."
    )


def test_spark_major_minor_is_4_0(spark: SparkSession) -> None:
    assert spark.version.startswith("4.0."), f"Expected Spark 4.0.x, found {spark.version}"


def test_session_timezone_is_utc(spark: SparkSession) -> None:
    assert spark.conf.get("spark.sql.session.timeZone") == "UTC"


@pytest.mark.local_spark
def test_delta_jars_are_scala_213(spark: SparkSession) -> None:
    """Databricks env 5 runs Scala 2.13; a 2.12 JAR would fail on deploy.

    Classic-only: spark.jars.packages is a launcher config with no Connect
    equivalent, since Connect resolves JARs server-side.
    """
    packages = spark.conf.get("spark.jars.packages", "") or ""
    assert "delta-spark_2.13" in packages, f"Delta JAR not Scala 2.13: {packages!r}"


def test_delta_round_trip(spark: SparkSession, tmp_path: Path) -> None:
    """Write and read a Delta table to prove extension, catalog, and JARs align."""
    path = str(tmp_path / "delta_smoke")
    spark.range(5).write.format("delta").mode("overwrite").save(path)
    assert spark.read.format("delta").load(path).count() == 5
