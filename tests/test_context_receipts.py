"""Tests for ContextReceiptV1 contract, bounded receipt persistence, and delivery evidence."""

from __future__ import annotations

import policies.api as api
from policies.api import ContextReceiptV1, RECEIPT_SCHEMA_VERSION


def test_context_receipt_v1_schema_contract() -> None:
    """Verify ContextReceiptV1 exports, required keys, and PEP 563 string annotations."""
    assert RECEIPT_SCHEMA_VERSION == 1
    assert "RECEIPT_SCHEMA_VERSION" in api.__all__
    assert "ContextReceiptV1" in api.__all__

    expected_annotations = {
        "schema_version": "int",
        "receipt_id": "str",
        "parent_event_id": "str | None",
        "timestamp": "str",
        "event_type": "str",
        "harness": "str",
        "session_id": "str",
        "workspace_id": "str",
        "turn_key": "str",
        "call_id": "str",
        "spool_id": "str",
        "line_span": "tuple[int, int]",
        "byte_span": "tuple[int, int]",
        "upstream_truncation": "bool",
        "delivery_evidence": "str",
        "spool_id_referenced": "bool",
        "failure_kind": "str | None",
        "reason": "str | None",
    }
    ann = ContextReceiptV1.__annotations__
    assert set(ann.keys()) == set(expected_annotations.keys())
    assert ContextReceiptV1.__required_keys__ == frozenset(expected_annotations.keys())
    for key, expected in expected_annotations.items():
        raw_val = ann[key]
        actual = raw_val if isinstance(raw_val, str) else getattr(raw_val, "__forward_arg__", repr(raw_val))
        assert actual == expected
