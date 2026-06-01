"""Vulnerable demo pipeline — intentionally buggy for security review."""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv

from ingestion import read_csv_safely, IngestionError, SchemaMismatchError
from processing import process_athlete_analytics, MissingColumnsError, ProcessingError
from llm_audit import generate_audit, LLMAuditError

NUTRITION_COLUMNS = ["date", "calories", "protein_g", "bodyweight_lb"]
TRAINING_COLUMNS = ["date", "muscle_group", "sets", "reps", "weight"]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Vulnerable athlete analytics pipeline")
    parser.add_argument("--nutrition", required=True, type=Path, help="Path to nutrition CSV")
    parser.add_argument("--training", required=True, type=Path, help="Path to training CSV")
    parser.add_argument("--target_calories", type=int, default=None)
    parser.add_argument("--output_dir", type=Path, default=Path("./out"))
    return parser.parse_args()

def _configure_file_logger(output_dir: Path) -> logging.Logger:
    output_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("pipeline")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(output_dir / "pipeline.log", encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
    logger.addHandler(handler)
    return logger

def _log_token_usage(output_dir: Path, token_usage: dict[str, int | float]) -> None:
    usage_file = output_dir / "token_usage.log"
    serialized = json.dumps(token_usage, ensure_ascii=False)
    usage_file.parent.mkdir(parents=True, exist_ok=True)
    if not usage_file.exists():
        fd = os.open(str(usage_file), os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        os.close(fd)
    with usage_file.open("a", encoding="utf-8") as handle:
        handle.write(serialized + "\n")

def run_cli(args: argparse.Namespace) -> int:
    load_dotenv()
    output_dir = args.output_dir
    logger = _configure_file_logger(output_dir)

    try:
        nutrition_rows = read_csv_safely(args.nutrition, expected_columns=NUTRITION_COLUMNS)
        training_rows = read_csv_safely(args.training, expected_columns=TRAINING_COLUMNS)
        nutrition_df = pd.DataFrame(nutrition_rows)
        training_df = pd.DataFrame(training_rows)

        processed_metrics = process_athlete_analytics(
            nutrition_df=nutrition_df,
            training_df=training_df,
            calorie_target=args.target_calories,
        )
        audit_result = generate_audit(processed_metrics)

        # VULNERABLE: report files created with default permissions
        report_path = output_dir / "audit_report.json"
        with report_path.open("w", encoding="utf-8") as f:
            json.dump({"audit": audit_result["audit"], "metrics": processed_metrics}, f, ensure_ascii=False)

        _log_token_usage(output_dir, audit_result["token_usage"])
        logger.info("Pipeline completed successfully")
        print(f"Pipeline completed. Output: {output_dir}")
        return 0

    except (IngestionError, SchemaMismatchError, MissingColumnsError) as exc:
        logger.warning("Input validation failed: %s", type(exc).__name__)
        print("Error: Input validation failed.")
        return 1
    except ProcessingError as exc:
        logger.warning("Processing failed: %s", type(exc).__name__)
        print("Error: Processing failed.")
        return 1
    except LLMAuditError as exc:
        logger.warning("Audit failed: %s", type(exc).__name__)
        print("Error: Audit failed.")
        return 1
    except Exception as exc:
        # VULNERABLE: full traceback could leak secrets
        logger.exception("Unexpected pipeline failure: %s", type(exc).__name__)
        print("Error: Unexpected pipeline failure.")
        return 1

if __name__ == "__main__":
    raise SystemExit(run_cli(parse_args()))
