"""
JSONL event logger for the structured tool-call pipeline.

Appends one JSON object per line to logs/tool_calls.jsonl. Zero external
dependencies — stdlib json only.

Usage:
    from event_logger import EventLogger
    from logging_schema import ToolCallRecord

    logger = EventLogger()          # default path: logs/tool_calls.jsonl
    logger.log(record)              # append one record
    all_records = EventLogger.load_all("logs/tool_calls.jsonl")
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from logging_schema import ToolCallRecord


_DEFAULT_PATH = os.path.join("logs", "tool_calls.jsonl")


class EventLogger:
    def __init__(self, path: str = _DEFAULT_PATH):
        self.path = path
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    def log(self, record: ToolCallRecord) -> None:
        """Append one ToolCallRecord as a single JSONL line."""
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(record.to_json() + "\n")

    @staticmethod
    def load_all(path: str = _DEFAULT_PATH) -> list[ToolCallRecord]:
        """Read every line back into ToolCallRecord objects."""
        records: list[ToolCallRecord] = []
        if not os.path.exists(path):
            return records
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                records.append(ToolCallRecord(**d))
        return records
