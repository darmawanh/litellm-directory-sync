"""Hand-built ``objectGUID`` samples for the T-007 spike.

AD sends ``objectGUID`` as 16 raw bytes. The byte order is *mixed-endian*:
the first three UUID fields (``time_low``, ``time_mid``,
``time_hi_and_version``) are little-endian, and the last two (``clock_seq`` and
``node``) are big-endian. ``uuid.UUID (bytes_le=raw)`` is the correct
interpretation; ``uuid.UUID (bytes=raw)`` is not.

Each entry pairs the wire bytes with the canonical UUID string the adapter must
produce. The samples are synthetic, chosen to exercise the byte order, not
copied from a directory.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ObjectGuidSample:
    """One wire value and the canonical string it must become."""

    name: str
    raw: bytes
    expected: str
    why: str


SAMPLES: tuple[ObjectGuidSample, ...] = (
    ObjectGuidSample(
        name="typical",
        raw=bytes.fromhex("4a3b2c1d5e6f47a8b9c0d1e2f3a4b5c6"),
        expected="1d2c3b4a-6f5e-a847-b9c0-d1e2f3a4b5c6",
        why="ordinary value; proves the first three fields are byte-swapped",
    ),
    ObjectGuidSample(
        name="zero_byte",
        raw=bytes.fromhex("00112233445566778899aabbccddeeff"),
        expected="33221100-5544-7766-8899-aabbccddeeff",
        why="contains 0x00; rules out a C-string or text-decoding path",
    ),
    ObjectGuidSample(
        name="high_bit_byte",
        raw=bytes.fromhex("ffeeddccbbaa99887766554433221100"),
        expected="ccddeeff-aabb-8899-7766-554433221100",
        why="every byte has the high bit set; rules out signed-byte handling",
    ),
    ObjectGuidSample(
        name="version_and_variant_nibbles",
        raw=bytes.fromhex("d3a1f0b24c8e4f6a9b7c5d3e1f2a4b6c"),
        expected="b2f0a1d3-8e4c-6a4f-9b7c-5d3e1f2a4b6c",
        why="version nibble 6 and variant nibble 9 survive the swap unchanged",
    ),
    ObjectGuidSample(
        name="interior_zero_run",
        raw=bytes.fromhex("0102030405060700000a0b0c0d0e0f10"),
        expected="04030201-0605-0007-000a-0b0c0d0e0f10",
        why="zero run crosses the time_hi/clock_seq boundary",
    ),
)

SAMPLE_BY_NAME: dict[str, ObjectGuidSample] = {sample.name: sample for sample in SAMPLES}
