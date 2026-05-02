"""Helpers to extract structured data from on-device Realm JSON dumps.

The exported Realm files from `assa-store.realm`, `timeseries-store.realm`, and
`events-store.realm` are flat lists where:
  - item 0 is a `class_name → table_id` header
  - subsequent items are rows (dicts) and references (strings/lists)

This module surfaces the data classes a downstream consumer typically wants:

  - DailyReadiness scores + sub-score contributors
  - DailySleep scores + sub-score contributors + biometrics
  - DailyActivity (calories, MET, distance)
  - Bio time-series: HR (BPM), HRV (RMSSD ms), Temperature (7 channels in °C),
    Motion (acm + orientation), Step counts

The Realm dump format strips raw byte blobs (`DbRawEvent.data` references resolve
to empty `{}`), so this module focuses on the structured tables.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


# ----- low-level loading -----

def _load(path: str | Path) -> list:
    return json.load(open(path))


def _is_row(r: Any, keys: set[str]) -> bool:
    """A 'row' is a dict whose keys form a recognizable shape."""
    return isinstance(r, dict) and keys.issubset(r.keys())


# ----- daily summaries (assa-store.json) -----


def daily_readiness(assa_path: str | Path) -> Iterator[dict]:
    """Yield each DailyReadiness top-level row (one per day)."""
    score_keys = {"score", "sleep_algorithm_version"}
    for r in _load(assa_path):
        if _is_row(r, score_keys) and "sleep_debt" not in r:
            yield r


def daily_sleep(assa_path: str | Path) -> Iterator[dict]:
    """Yield each DailySleep top-level row (one per night)."""
    keys = {"score", "sleep_algorithm_version", "sleep_debt"}
    for r in _load(assa_path):
        if _is_row(r, keys):
            yield r


def daily_sleep_biometrics(assa_path: str | Path) -> Iterator[dict]:
    """Yield each DailySleep biometric-summary row (avg HR, avg HRV, REM/NREM
    HRV, breathing rate, awake_time, etc.).
    """
    keys = {"average_breath", "average_heart_rate", "average_hrv",
            "awake_time", "bedtime_end"}
    for r in _load(assa_path):
        if _is_row(r, keys):
            yield r


def daily_activity(assa_path: str | Path) -> Iterator[dict]:
    """Yield each DailyActivity row (calories, MET, equivalent walking distance)."""
    keys = {"active_calories", "active_time", "average_met_minutes",
            "equivalent_walking_distance"}
    for r in _load(assa_path):
        if _is_row(r, keys):
            yield r


def readiness_contributors(assa_path: str | Path) -> Iterator[dict]:
    """Yield per-day readiness sub-score breakdowns:
        activity_balance, body_temperature, hrv_balance, previous_day_activity,
        previous_night, recovery_index, resting_heart_rate, sleep_balance,
        sleep_regularity (each 0-100, or null when not yet computed).
    """
    keys = {"activity_balance", "hrv_balance", "recovery_index", "resting_heart_rate"}
    for r in _load(assa_path):
        if _is_row(r, keys):
            yield r


def sleep_contributors(assa_path: str | Path) -> Iterator[dict]:
    """Yield per-night sleep sub-score breakdowns:
        deep_sleep, efficiency, latency, rem_sleep, restfulness, timing,
        total_sleep (each 0-100).
    """
    keys = {"deep_sleep", "rem_sleep", "efficiency", "latency", "timing", "total_sleep"}
    for r in _load(assa_path):
        if _is_row(r, keys):
            yield r


def daily_breathing(assa_path: str | Path) -> Iterator[dict]:
    """Yield breathing-disturbance / SpO2 daily summaries (BDI, OVI)."""
    keys = {"breathing_disturbance_index", "oxygen_variation_index"}
    for r in _load(assa_path):
        if _is_row(r, keys):
            yield r


# ----- time-series bio data (timeseries-store.json) -----


def heart_rate_samples(ts_path: str | Path) -> Iterator[dict]:
    """Yield per-2-minute HR/HRV samples (post-processed by libappecore):
        timestamp (ms), bpm, hrv (ms RMSSD), hrv_accuracy, ibi_quality,
        measurement_duration (s), restorative.
    """
    keys = {"bpm", "hrv", "hrv_accuracy"}
    for r in _load(ts_path):
        if _is_row(r, keys):
            yield r


def temperature_samples(ts_path: str | Path) -> Iterator[dict]:
    """Yield TempEvent rows after libringeventparser decoding (one row per
    sample, all 7 channels in °C; missing channels are -327.68 sentinel).
    """
    keys = {"temperature_1", "temperature_2", "temperature_3"}
    for r in _load(ts_path):
        if _is_row(r, keys):
            yield r


def motion_samples(ts_path: str | Path) -> Iterator[dict]:
    """Yield 4-second motion windows (acm averages, motion seconds, orientation)."""
    keys = {"acm_average_x", "acm_average_y", "acm_average_z"}
    for r in _load(ts_path):
        if _is_row(r, keys):
            yield r


def step_count_samples(ts_path: str | Path) -> Iterator[dict]:
    """Yield per-minute step-count windows."""
    keys = {"steps", "end_time", "producer_timestamp"}
    for r in _load(ts_path):
        if _is_row(r, keys):
            yield r


# ----- summary helpers -----


@dataclass
class DaySummary:
    """One day's worth of headline metrics."""
    timestamp: int
    readiness_score: int | None
    sleep_score: int | None
    avg_hr: float | None
    avg_hrv: int | None
    awake_time_s: int | None
    active_calories: float | None


def summarize_assa(assa_path: str | Path) -> list[DaySummary]:
    """Roll up assa-store into a list of one-line-per-day summaries.

    Joining is heuristic (by `day` string ID); the dump's references aren't
    fully resolved here. Use this for at-a-glance display, not analytics.
    """
    by_day: dict[str, dict] = {}
    for r in _load(assa_path):
        if not isinstance(r, dict): continue
        d = r.get("day")
        if d is None: continue
        by_day.setdefault(str(d), {}).update(r)

    out: list[DaySummary] = []
    for d, agg in sorted(by_day.items()):
        out.append(DaySummary(
            timestamp=agg.get("timestamp", 0),
            readiness_score=agg.get("score") if "sleep_debt" not in agg else None,
            sleep_score=agg.get("score") if "sleep_debt" in agg else None,
            avg_hr=agg.get("average_heart_rate"),
            avg_hrv=agg.get("average_hrv"),
            awake_time_s=agg.get("awake_time"),
            active_calories=agg.get("active_calories"),
        ))
    return out
