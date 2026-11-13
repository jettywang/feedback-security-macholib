"""Interval arithmetic and encryption-coverage classification.

Everything here works on *file* offsets (``[start, start+length)``) because
``LC_ENCRYPTION_INFO*`` describes a region of the on-disk file, not a virtual
memory range. The module is deliberately free of any Mach-O knowledge so the
classification rules are easy to audit on their own.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Interval:
    """A half-open byte range ``[start, end)`` inside the file."""

    start: int
    end: int
    label: str = ""

    @property
    def size(self):
        return max(0, self.end - self.start)

    def __post_init__(self):
        if self.end < self.start:
            raise ValueError("interval end precedes start: %r" % (self,))


def intersect(a, b):
    """Return the overlap of two intervals, or ``None`` when disjoint."""
    lo = max(a.start, b.start)
    hi = min(a.end, b.end)
    if lo < hi:
        return Interval(lo, hi, a.label + "&" + b.label)
    return None


def overlap_size(a, b):
    hit = intersect(a, b)
    return 0 if hit is None else hit.size


def classify_against(region, crypto):
    """Split ``region`` into encrypted / clear portions relative to ``crypto``.

    ``crypto`` is the declared encryption window (or ``None`` when the image
    carries no active encryption command). Returns a dict with the three
    mutually exclusive byte counts and, when present, the actual sub-ranges.
    """
    if crypto is None or crypto.size == 0:
        return {
            "state": "no-encryption-command",
            "encrypted": 0,
            "clear": region.size,
            "encrypted_ranges": [],
            "clear_ranges": [Interval(region.start, region.end, region.label)],
        }

    hit = intersect(region, crypto)
    if hit is None:
        return {
            "state": "fully-clear",
            "encrypted": 0,
            "clear": region.size,
            "encrypted_ranges": [],
            "clear_ranges": [Interval(region.start, region.end, region.label)],
        }

    encrypted_ranges = []
    clear_ranges = []
    if region.start < crypto.start:
        clear_ranges.append(
            Interval(region.start, min(region.end, crypto.start), region.label)
        )
    encrypted_ranges.append(hit)
    if region.end > crypto.end:
        clear_ranges.append(
            Interval(max(region.start, crypto.end), region.end, region.label)
        )

    encrypted = sum(r.size for r in encrypted_ranges)
    clear = sum(r.size for r in clear_ranges)
    if encrypted == region.size:
        state = "fully-encrypted"
    elif clear == region.size:
        state = "fully-clear"
    else:
        state = "partially-encrypted"
    return {
        "state": state,
        "encrypted": encrypted,
        "clear": clear,
        "encrypted_ranges": encrypted_ranges,
        "clear_ranges": clear_ranges,
    }


def shannon_entropy(data):
    """Shannon entropy in bits/byte, used descriptively only.

    A high value cannot identify a packer on its own: compressed resources,
    already-encrypted FairPlay pages and random data all look alike here.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * __import__("math").log2(p)
    return entropy
