"""Tests for the non-decrypting static-analysis demo.

These assert classification logic and cross-range invariants; they never
execute a sample and never attempt decryption.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

import analyzer
import ranges
import sample_generator as gen


def test_classify_disjoint_is_fully_clear():
    region = ranges.Interval(0, 100)
    crypto = ranges.Interval(200, 300)
    result = ranges.classify_against(region, crypto)
    assert result["state"] == "fully-clear"
    assert result["clear"] == 100 and result["encrypted"] == 0


def test_classify_fully_encrypted():
    region = ranges.Interval(40, 90)
    crypto = ranges.Interval(0, 100)
    result = ranges.classify_against(region, crypto)
    assert result["state"] == "fully-encrypted"
    assert result["encrypted"] == 50 and result["clear"] == 0


def test_classify_partial_splits_bytes():
    region = ranges.Interval(0, 100)
    crypto = ranges.Interval(40, 90)
    result = ranges.classify_against(region, crypto)
    assert result["state"] == "partially-encrypted"
    assert result["encrypted"] == 50
    assert result["clear"] == 50
    assert result["encrypted"] + result["clear"] == region.size


def test_no_crypto_treats_everything_as_clear():
    result = ranges.classify_against(ranges.Interval(0, 10), None)
    assert result["state"] == "no-encryption-command"
    assert result["clear"] == 10


def test_entropy_bounds_and_empty():
    assert ranges.shannon_entropy(b"") == 0.0
    assert 0.0 <= ranges.shannon_entropy(b"aaaa") <= 8.0
    assert ranges.shannon_entropy(bytes(range(256))) > 7.9


def _arch(scenario):
    blob, _layout = gen.build_slice(scenario)
    return analyzer.analyze(blob)["architectures"][0]


def test_fairplay_text_encrypted_but_metadata_readable():
    arch = _arch("fairplay")
    assert arch["encryption"]["active"] is True
    # Entry location is known even though the instruction bytes are opaque.
    assert arch["entry"]["location_known"] is True
    assert arch["entry"]["instructions_readable"] is False
    # Dependencies live in load commands and are always reportable.
    assert arch["dependencies"][0]["path"] == "/usr/lib/libSystem.B.dylib"
    # Linkedit sits beyond the crypt window in the normal layout.
    assert all(row["parseable"] for row in arch["linkedit"])
    assert arch["symbols"]["names_resolvable"] is True
    assert arch["range_conflicts"] == []


def test_conflict_flags_overrun_and_linkedit_overlap():
    arch = _arch("conflict")
    joined = " ".join(arch["range_conflicts"])
    assert "past end of file" in joined
    assert "__LINKEDIT" in joined
    # Symbols now fall inside the oversized window -> metadata only.
    assert arch["symbols"]["names_resolvable"] is False
    assert any(not row["parseable"] for row in arch["linkedit"])


def test_unencrypted_command_is_dormant_not_active():
    arch = _arch("unencrypted")
    enc = arch["encryption"]
    assert enc["declared"] is True and enc["active"] is False
    assert any("dormant" in n for n in enc["diagnostics"])
    assert arch["entry"]["instructions_readable"] is True


def test_malformed_zero_size_is_flagged():
    arch = _arch("malformed")
    assert arch["encryption"]["active"] is False
    assert any("inconsistent" in n
               for n in arch["encryption"]["diagnostics"])


def test_zerofill_section_counts_no_file_bytes():
    arch = _arch("fairplay")
    data_seg = next(s for s in arch["segments"] if s["name"] == "__DATA")
    bss = next(s for s in data_seg["sections"] if s["name"] == "__bss")
    assert bss["state"] == "zerofill/no-file-bytes"
    assert bss["encrypted"] == 0 and bss["clear"] == 0


def test_byte_accounting_balances_per_segment():
    for scenario in gen.SCENARIOS:
        arch = _arch(scenario)
        for seg in arch["segments"]:
            counted = seg["encrypted_bytes"] + seg["clear_bytes"]
            start, end = seg["file_range"]
            assert counted <= (end - start)


def test_fat_container_reports_both_slices():
    blob, _layout = gen.build_fat("fairplay")
    report = analyzer.analyze(blob)
    assert report["fat"] is True
    assert len(report["architectures"]) == 2
    assert {a["identity"]["cputype"] for a in report["architectures"]} == {
        0x01000000 | 12, 0x01000000 | 7}


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
