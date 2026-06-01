"""Mitigated ingestion module — hardened against path traversal and symlink attacks."""

from __future__ import annotations

import csv
import os
from pathlib import Path
from typing import Any

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_ROW_COUNT = 10_000

class IngestionError(Exception):
    """Raised when ingestion operations fail."""

class SchemaMismatchError(IngestionError):
    """Raised when CSV schema does not match expected columns."""
    pass

class SecurityError(IngestionError):
    """Raised when a security policy is violated."""
    pass

def sanitize_csv_row(row: dict[str, str]) -> dict[str, str]:
    """Sanitize a CSV row with length limits."""
    sanitized: dict[str, str] = {}
    for key, value in row.items():
        safe_key = key.strip().replace("\x00", "") if key is not None else ""
        safe_value = value.strip().replace("\x00", "") if value is not None else ""
        if len(safe_key) > 128 or len(safe_value) > 1024:
            raise SecurityError("CSV field exceeds maximum allowed length")
        sanitized[safe_key] = safe_value
    return sanitized

def _validate_path(file_path: Path, base_dir: Path | None = None) -> Path:
    """Resolve path, reject symlinks and directory traversal."""
    if file_path.is_symlink() or os.path.islink(str(file_path)):
        raise SecurityError("Symlinks are not allowed for CSV input")
    abs_path = file_path.resolve()
    if base_dir is not None:
        base_dir = base_dir.resolve()
        try:
            abs_path.relative_to(base_dir)
        except ValueError:
            raise SecurityError(f"Path must be within {base_dir}")
    return abs_path

def _validate_file_size(file_path: Path) -> None:
    size = file_path.stat().st_size
    if size > MAX_FILE_SIZE_BYTES:
        raise SecurityError(f"File size {size} exceeds maximum {MAX_FILE_SIZE_BYTES}")

def _validate_row_count(file_path: Path) -> None:
    with file_path.open("r", encoding="utf-8") as handle:
        for i, _ in enumerate(handle):
            if i >= MAX_ROW_COUNT:
                raise SecurityError(f"CSV exceeds maximum {MAX_ROW_COUNT} rows")

def read_csv_safely(
    file_path: Path,
    expected_columns: list[str] | None = None,
    base_dir: Path | None = None,
) -> list[dict[str, Any]]:
    """Read CSV — MITIGATED: path validation, symlink check, size limits."""
    abs_path = _validate_path(file_path, base_dir)
    if not abs_path.exists() or not abs_path.is_file():
        raise IngestionError(f"CSV file not found: {abs_path}")
    if abs_path.suffix.lower() != ".csv":
        raise IngestionError("Only .csv files are allowed")

    _validate_file_size(abs_path)
    _validate_row_count(abs_path)

    rows: list[dict[str, Any]] = []
    try:
        with abs_path.open("r", newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if expected_columns is not None:
                actual_columns = set(reader.fieldnames or [])
                expected_set = set(expected_columns)
                if not expected_set.issubset(actual_columns):
                    missing = expected_set - actual_columns
                    raise SchemaMismatchError(f"Missing required columns: {missing}")
            for row in reader:
                rows.append(sanitize_csv_row(row))
    except SchemaMismatchError:
        raise
    except (OSError, csv.Error) as exc:
        raise IngestionError("Failed to ingest CSV data") from exc
    return rows
