"""Mitigated demo pipeline — hardened with secret scrubbing, audit logging, and permission checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

from ingestion import read_csv_safely, IngestionError, SchemaMismatchError, SecurityError as IngestionSecurityError
from processing import process_athlete_analytics, MissingColumnsError, ProcessingError, SecurityError as ProcessingSecurityError
from llm_audit import generate_audit, LLMAuditError

NUTRITION_COLUMNS = ["date", "calories", "protein_g", "bodyweight_lb"]
TRAINING_COLUMNS = ["date", "muscle_group", "sets", "reps", "weight"]

class SecretScrubbingFormatter(logging.Formatter):
    """Log formatter that redacts common secret patterns."""
    _SECRET_PATTERNS = [
        re.compile(r"sk-[A-Za-z0-9]{20,}"),
        re.compile(r"OPENAI_API_KEY\s*=\s*[^\s]+"),
        re.compile(r"Bearer\s+[A-Za-z0-9_-]+"),
    ]

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        for pattern in self._SECRET_PATTERNS:
            msg = pattern.sub("[REDACTED]", msg)
        return msg

def _check_env_permissions() -> None:
    """Ensure .env file is not readable by others."""
    env_path = Path(".env")
    if not env_path.exists():
        return
    mode = env_path.stat().st_mode
    if mode & 0o077:
        raise PermissionError(
            f".env file has permissions {oct(mode & 0o777)}. Run: chmod 600 .env"
        )

def _secure_makedirs(path: Path) -> None:
    """Create directory with restricted permissions."""
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Double-check existing dirs
    if path.exists() and (path.stat().st_mode & 0o077):
        os.chmod(str(path), 0o700)

def _configure_file_logger(output_dir: Path) -> logging.Logger:
    _secure_makedirs(output_dir)
    logger = logging.getLogger("pipeline")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(output_dir / "pipeline.log", encoding="utf-8")
    handler.setFormatter(SecretScrubbingFormatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(handler)
    return logger

def _configure_audit_logger(output_dir: Path) -> logging.Logger:
    _secure_makedirs(output_dir)
    logger = logging.getLogger("audit")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(output_dir / "audit.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger

def _log_token_usage(output_dir: Path, token_usage: dict[str, int | float]) -> None:
    usage_file = output_dir / "token_usage.log"
    serialized = json.dumps(token_usage, ensure_ascii=False)
    _secure_makedirs(output_dir)
    if not usage_file.exists():
        fd = os.open(str(usage_file), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        os.close(fd)
    with usage_file.open("a", encoding="utf-8") as handle:
        handle.write(serialized + "\n")

def _write_json_report(data: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.chmod(str(path), 0o600)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mitigated athlete analytics pipeline")
    parser.add_argument("--nutrition", required=True, type=Path, help="Path to nutrition CSV")
    parser.add_argument("--training", required=True, type=Path, help="Path to training CSV")
    parser.add_argument("--target_calories", type=int, default=None)
    parser.add_argument("--output_dir", type=Path, default=Path("./out"))
    parser.add_argument("--live", action="store_true", help="Enable live LLM calls (requires consent)")
    parser.add_argument("--data-dir", type=Path, default=Path("."), help="Base directory for input validation")
    return parser.parse_args()

def run_cli(args: argparse.Namespace) -> int:
    load_dotenv()
    _check_env_permissions()

    output_dir = args.output_dir
    logger = _configure_file_logger(output_dir)
    audit_logger = _configure_audit_logger(output_dir)

    try:
        nutrition_rows = read_csv_safely(
            args.nutrition, expected_columns=NUTRITION_COLUMNS, base_dir=args.data_dir
        )
        training_rows = read_csv_safely(
            args.training, expected_columns=TRAINING_COLUMNS, base_dir=args.data_dir
        )
        nutrition_df = pd.DataFrame(nutrition_rows)
        training_df = pd.DataFrame(training_rows)

        processed_metrics = process_athlete_analytics(
            nutrition_df=nutrition_df,
            training_df=training_df,
            calorie_target=args.target_calories,
        )
        audit_result = generate_audit(processed_metrics, allow_remote=args.live)

        report_path = output_dir / "audit_report.json"
        _write_json_report({
            "audit": audit_result["audit"],
            "metrics": processed_metrics,
            "non_repudiation": audit_result.get("non_repudiation"),
        }, report_path)

        _log_token_usage(output_dir, audit_result["token_usage"])

        audit_logger.info(json.dumps({
            "event": "pipeline_complete",
            "input_nutrition": str(args.nutrition),
            "input_training": str(args.training),
            "output_hash": hashlib.sha256(report_path.read_bytes()).hexdigest()[:16],
            "token_usage": audit_result["token_usage"],
            "live_llm": args.live,
        }))

        logger.info("Pipeline completed successfully")
        print(f"Pipeline completed. Output: {output_dir}")
        return 0

    except (IngestionError, SchemaMismatchError, IngestionSecurityError,
            MissingColumnsError, ProcessingError, ProcessingSecurityError) as exc:
        logger.error("Input/processing error: %s", type(exc).__name__, exc_info=False)
        print("Error: Input validation or processing failed.")
        return 1
    except LLMAuditError as exc:
        logger.error("Audit error: %s", type(exc).__name__, exc_info=False)
        print("Error: Audit generation failed.")
        return 1
    except PermissionError as exc:
        logger.error("Permission error: %s", exc)
        print(f"Error: {exc}")
        return 1
    except Exception as exc:
        # MITIGATED: no full traceback, no exception object in log
        logger.error("Unexpected pipeline failure: %s", type(exc).__name__, exc_info=False)
        print("Error: Unexpected pipeline failure.")
        return 1

if __name__ == "__main__":
    raise SystemExit(run_cli(parse_args()))
