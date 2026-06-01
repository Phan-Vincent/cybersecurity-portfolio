"""Mitigated processing module — hardened with input whitelisting and validation."""

from __future__ import annotations

from typing import Any
import pandas as pd

class ProcessingError(Exception):
    """Raised when processing operations fail."""

class MissingColumnsError(ProcessingError):
    """Raised when required columns are missing."""

class SecurityError(ProcessingError):
    """Raised when a security policy is violated."""
    pass

NUTRITION_COLS = ["date", "calories", "protein_g", "bodyweight_lb"]
TRAINING_COLS = ["date", "muscle_group", "sets", "reps", "weight"]

VALID_MUSCLE_GROUPS = {
    "Chest", "Back", "Legs", "Shoulders", "Arms", "Biceps", "Triceps",
    "Core", "Abs", "Calves", "Forearms", "Glutes", "Hamstrings", "Quads",
    "Traps", "Lats", "Lower Back", "Upper Back", "Neck", "Cardio",
}

MAX_MUSCLE_GROUP_LEN = 32

def _require_columns(frame: pd.DataFrame, required: list[str], frame_name: str) -> None:
    missing = [c for c in required if c not in frame.columns]
    if missing:
        raise MissingColumnsError(f"{frame_name} missing required columns: {missing}")

def _validate_muscle_group(value: str) -> str:
    """Reject unknown or suspicious muscle group names."""
    cleaned = value.strip()
    if len(cleaned) > MAX_MUSCLE_GROUP_LEN:
        raise SecurityError(f"muscle_group too long: {len(cleaned)} chars")
    if cleaned not in VALID_MUSCLE_GROUPS:
        raise SecurityError(f"Invalid muscle_group: {cleaned!r}. Allowed: {VALID_MUSCLE_GROUPS}")
    return cleaned

def compute_weekly_nutrition_metrics(nutrition_df: pd.DataFrame, calorie_target: float | None = None) -> dict[str, Any]:
    _require_columns(nutrition_df, NUTRITION_COLS, "nutrition")
    frame = nutrition_df.copy()
    for col in ["calories", "protein_g", "bodyweight_lb"]:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
    frame["date"] = pd.to_datetime(frame["date"], errors="coerce")
    frame["week_start"] = frame["date"].dt.to_period("W").dt.start_time.dt.strftime("%Y-%m-%d")

    weekly = frame.groupby("week_start", as_index=False).agg(
        avg_calories=("calories", "mean"),
        avg_protein_g=("protein_g", "mean"),
        avg_bodyweight_lb=("bodyweight_lb", "mean"),
    )
    weekly["protein_per_lb"] = weekly["avg_protein_g"] / weekly["avg_bodyweight_lb"]
    if calorie_target is not None and calorie_target > 0:
        weekly["calorie_adherence_pct"] = (weekly["avg_calories"] / calorie_target) * 100.0

    latest = weekly.iloc[-1] if not weekly.empty else None
    return {
        "weekly": weekly.to_dict("records"),
        "latest": latest.to_dict() if latest is not None else None,
    }

def compute_weekly_training_metrics(training_df: pd.DataFrame) -> dict[str, Any]:
    _require_columns(training_df, TRAINING_COLS, "training")
    frame = training_df.copy()
    for col in ["sets", "reps", "weight"]:
        frame[col] = pd.to_numeric(frame[col], errors="coerce")
    frame["date"] = pd.to_datetime(frame["date"], errors="coerce")
    frame["week_start"] = frame["date"].dt.to_period("W").dt.start_time.dt.strftime("%Y-%m-%d")
    frame["set_volume"] = frame["sets"].astype(float) * frame["reps"].astype(float) * frame["weight"].astype(float)

    # MITIGATED: validate muscle_group before aggregation
    frame["muscle_group"] = frame["muscle_group"].astype(str).apply(_validate_muscle_group)

    weekly_volume = frame.groupby(["week_start", "muscle_group"], as_index=False).agg(
        total_volume=("set_volume", "sum")
    )

    return {
        "weekly_volume_by_muscle_group": weekly_volume.to_dict("records"),
    }

def detect_risk_flags(nutrition_metrics: dict[str, Any]) -> list[str]:
    flags: list[str] = []
    latest = nutrition_metrics.get("latest")
    if latest:
        protein_per_lb = latest.get("protein_per_lb")
        if isinstance(protein_per_lb, (int, float)) and protein_per_lb < 0.8:
            flags.append("Protein intake below 0.8 g/lb")
    return flags

def process_athlete_analytics(
    nutrition_df: pd.DataFrame,
    training_df: pd.DataFrame,
    calorie_target: float | None = None,
) -> dict[str, Any]:
    nutrition_metrics = compute_weekly_nutrition_metrics(nutrition_df, calorie_target=calorie_target)
    training_metrics = compute_weekly_training_metrics(training_df)
    risk_flags = detect_risk_flags(nutrition_metrics)
    return {
        "nutrition_metrics": nutrition_metrics,
        "training_metrics": training_metrics,
        "risk_flags": risk_flags,
    }
