# src/spark_batch_pipeline/valuetypes.py
"""Semantic value types for the ingestion contracts.

PRIMITIVE OBSESSION IS A CORRECTNESS PROBLEM HERE, NOT A STYLE ONE.

    sha256: str = Field(min_length=64, max_length=64)

reads like a digest constraint and is not one. It accepts any 64 characters, so
64 copies of "Z" validate as a SHA-256. A sidecar corrupted into the right
LENGTH of garbage would be accepted as a trustworthy attestation -- exactly the
failure the digest exists to prevent.

That constraint was also written five times across fetch.py and extract.py: the
same shape duplicated, which the schema-first doctrine in context/ forbids on
Axis 2. One definition here, imported everywhere, so the rule cannot drift
between a manifest and the record that must agree with it.

STRICT MODE, AND WHERE IT APPLIES
Pydantic's default lax coercion is right for YAML and query strings, where
everything arrives as text. It is wrong at an attestation boundary: silently
turning 1.0 into 1, or True into 1, lets malformed data become apparently valid
data. The ingestion records therefore run strict.

Strict is deliberately NOT applied blanket. Pydantic is looser from JSON by
design, so a datetime still parses from an ISO string and the sidecar round trip
is unaffected -- but strict would reject a plain string for HttpUrl in config
parsed from YAML, where coercion is the correct behaviour. Applied where
verified, not everywhere.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AwareDatetime, Field, StringConstraints

# A SHA-256 digest as this project writes it: exactly 64 LOWERCASE hex digits.
# The pattern is the point; length alone is not a digest constraint.
#
# Lowercase specifically, because hashlib.hexdigest emits lowercase. Accepting
# mixed case would let two spellings of one digest compare unequal and report a
# false CORRUPT.
Sha256 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
    Field(description="SHA-256 digest, 64 lowercase hex digits"),
]

# CRC-32 as ZIP stores it: an unsigned 32-bit integer. The bounds are the type,
# not a sanity check -- a value outside them did not come from a CRC.
Crc32 = Annotated[
    int,
    Field(ge=0, le=0xFFFFFFFF, description="CRC-32 checksum, unsigned 32-bit"),
]

# A filesystem path recorded for provenance. Empty is never meaningful: a record
# claiming it came from nowhere attests nothing.
PathString = Annotated[
    str,
    StringConstraints(min_length=1, strip_whitespace=True),
    Field(description="Non-empty filesystem path, recorded for provenance"),
]

# An archive member name. Path separators and traversal are rejected at the TYPE
# level, not merely by the extraction policy, so a record can never claim a
# member that policy would have refused to extract.
MemberName = Annotated[
    str,
    StringConstraints(min_length=1, pattern=r"^[^/\\]+$"),
    Field(description="Archive member name, no path separators"),
]

# The URL a manifest records, kept as the EXACT string that was requested.
#
# Deliberately not HttpUrl, and the distinction matters. HttpUrl is the right
# type in conf/pipeline.yml, where the job is to REJECT input that is not a
# usable URL. Here the job is to RECORD what actually happened, and HttpUrl in
# Pydantic v2 is a Url object rather than a str: it normalizes, so a stored URL
# can differ from the one that was fetched. A provenance record must not
# silently attest a request that was never made.
RecordedUrl = Annotated[
    str,
    StringConstraints(min_length=1),
    Field(description="Verbatim URL as requested; not normalized"),
]

# A byte count. Zero is legal: an empty member is unusual, not invalid.
ByteCount = Annotated[int, Field(ge=0, description="Size in bytes")]

# A timestamp that MUST carry a timezone. Plain `datetime` accepts a naive
# value, and a naive timestamp in an attestation is ambiguous: it does not say
# when the artifact was actually ingested, so two records from machines in
# different zones cannot be ordered. Everything here is produced with
# datetime.now(UTC); AwareDatetime makes that a requirement rather than a habit.
UtcTimestamp = Annotated[
    AwareDatetime,
    Field(description="Timezone-aware timestamp; naive values are rejected"),
]
