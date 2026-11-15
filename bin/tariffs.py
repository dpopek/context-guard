"""Dated API list-price tariffs and pure per-turn / per-group cost attribution."""

from __future__ import annotations

from typing import Any, Mapping

TARIFF_EFFECTIVE_DATE = "2026-11-01"

# USD per 1M tokens: (input, cache_write, cache_read, output) as of TARIFF_EFFECTIVE_DATE.
MODEL_TARIFFS_PER_M: dict[str, tuple[float, float, float, float]] = {
    "claude-opus-4-6": (15.0, 18.75, 1.50, 75.0),
    "claude-opus-4-5": (15.0, 18.75, 1.50, 75.0),
    "claude-opus-4-1": (15.0, 18.75, 1.50, 75.0),
    "claude-opus-4": (15.0, 18.75, 1.50, 75.0),
    "claude-sonnet-4-6": (3.0, 3.75, 0.30, 15.0),
    "claude-sonnet-4-5": (3.0, 3.75, 0.30, 15.0),
    "claude-sonnet-4": (3.0, 3.75, 0.30, 15.0),
    "claude-haiku-4-5": (1.0, 1.25, 0.10, 5.0),
    "claude-3-5-haiku": (0.80, 1.00, 0.08, 4.0),
    "gpt-5.4": (2.50, 2.50, 0.25, 15.0),
    "gpt-5-mini": (0.25, 0.25, 0.025, 2.0),
    "gpt-5": (1.25, 1.25, 0.125, 10.0),
    "gpt-4.1-mini": (0.40, 0.40, 0.10, 1.60),
    "gpt-4.1": (2.00, 2.00, 0.50, 8.0),
    "gpt-4o-mini": (0.15, 0.15, 0.075, 0.60),
    "gpt-4o": (2.50, 2.50, 1.25, 10.0),
    "o4-mini": (1.10, 1.10, 0.275, 4.40),
    "o3": (2.00, 2.00, 0.50, 8.0),
    "gemini-3.1-pro": (2.00, 2.00, 0.20, 12.0),
    "gemini-3-flash": (0.50, 0.50, 0.05, 3.0),
    "gemini-2.5-pro": (1.25, 1.25, 0.3125, 10.0),
    "gemini-2.5-flash": (0.30, 0.30, 0.075, 2.50),
}

_SORTED_PREFIXES = tuple(sorted(MODEL_TARIFFS_PER_M, key=len, reverse=True))
_PROVIDER_PREFIXES = ("models/", "anthropic/", "openai/", "google/")


def _nonneg_int(val: Any) -> int:
    try:
        return max(0, int(val or 0))
    except (TypeError, ValueError):
        return 0


def resolve_model_tariff(model: str | None) -> tuple[float, float, float, float] | None:
    """Resolve `(input, cache_write, cache_read, output)` USD/1M list prices or None if unpriced."""
    if not isinstance(model, str):
        return None
    norm = model.strip().lower()
    for pfx in _PROVIDER_PREFIXES:
        if norm.startswith(pfx):
            norm = norm[len(pfx) :]
            break
    if not norm or norm == "unknown":
        return None
    if norm in MODEL_TARIFFS_PER_M:
        return MODEL_TARIFFS_PER_M[norm]
    for candidate in _SORTED_PREFIXES:
        if norm.startswith(candidate + "-") or norm.startswith(candidate + ".") or norm.startswith(candidate + ":"):
            return MODEL_TARIFFS_PER_M[candidate]
    return None


def compute_turn_tariff_cost_usd(
    model: str | None,
    *,
    input_tokens: int = 0,
    cache_write_tokens: int = 0,
    cache_read_tokens: int = 0,
    output_tokens: int = 0,
    total_only: int | bool = False,
) -> float | None:
    """Pure USD cost calculation (`/ 1_000_000.0`); returns None for unpriced or total-only entries."""
    if total_only:
        return None
    rates = resolve_model_tariff(model)
    if rates is None:
        return None
    p_in, p_cw, p_cr, p_out = rates
    return (
        _nonneg_int(input_tokens) * p_in
        + _nonneg_int(cache_write_tokens) * p_cw
        + _nonneg_int(cache_read_tokens) * p_cr
        + _nonneg_int(output_tokens) * p_out
    ) / 1_000_000.0


def attribute_turn_cost(totals: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Attribute measured list-price USD and mean per-event cost across `(harness|model)` totals."""
    if not isinstance(totals, Mapping):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for key, raw in totals.items():
        if not isinstance(key, str) or "|" not in key or not isinstance(raw, Mapping):
            continue
        harness, _, model = key.partition("|")
        events = _nonneg_int(raw.get("events"))
        total_only = _nonneg_int(raw.get("total_only"))
        if events <= 0 or total_only >= events:
            measured = None
            mean_event = None
        else:
            measured = compute_turn_tariff_cost_usd(
                model,
                input_tokens=_nonneg_int(raw.get("input")),
                cache_write_tokens=_nonneg_int(raw.get("cache_write")),
                cache_read_tokens=_nonneg_int(raw.get("cache_read")),
                output_tokens=_nonneg_int(raw.get("output")),
            )
            mean_event = (measured / events) if measured is not None else None
        out[key] = {
            "harness": harness,
            "model": model,
            "events": events,
            "measured_cost_usd": measured,
            "mean_event_cost_usd": mean_event,
            "tariff_effective_date": TARIFF_EFFECTIVE_DATE,
        }
    return out
