# tests/conftest.py
"""Shared pytest fixtures.

Session-scoped because JVM startup dominates runtime: seconds per session
versus milliseconds per query. The session itself is built by
spark_batch_pipeline.session so tests exercise the same configuration the
pipeline uses, rather than a parallel copy that can drift.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from pyspark.sql import SparkSession

from spark_batch_pipeline.session import build_local_session


@pytest.fixture(scope="session")
def spark() -> Iterator[SparkSession]:
    session = build_local_session(app_name="spark-batch-pipeline-tests")
    session.sparkContext.setLogLevel("WARN")
    yield session
    session.stop()
