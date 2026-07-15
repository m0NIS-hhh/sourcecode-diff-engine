from __future__ import annotations

import glob
import logging
import os
import tempfile
import zipfile
from datetime import datetime

_LOGGER_NAME = "source_diff_analyzer"


class _ConsoleFormatter(logging.Formatter):

    def format(self, record: logging.LogRecord) -> str:
        original_exc_info = record.exc_info
        original_exc_text = getattr(record, "exc_text", None)
        try:
            record.exc_info = None
            record.exc_text = None
            return super().format(record)
        finally:
            record.exc_info = original_exc_info
            record.exc_text = original_exc_text


def compress_old_logs(log_dir: str = os.path.join("artifacts", "logs")) -> None:
    if not os.path.isdir(log_dir):
        return

    today = datetime.now().strftime("%Y%m%d")
    pattern = os.path.join(log_dir, "source_diff_analyzer_*.log")
    for log_path in glob.glob(pattern):
        filename = os.path.basename(log_path)
        if filename.startswith(f"source_diff_analyzer_{today}"):
            continue
        zip_path = f"{log_path}.zip"
        if os.path.exists(zip_path):
            continue
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                zipf.write(log_path, arcname=filename)
            os.remove(log_path)
        except Exception:
            continue


def setup_logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    if logger.handlers:
        return logger

    log_dir = os.path.join("artifacts", "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
        compress_old_logs(log_dir)
    except Exception:
        log_dir = os.path.join(tempfile.gettempdir(), "source_diff_analyzer_logs")
        os.makedirs(log_dir, exist_ok=True)
        compress_old_logs(log_dir)

    formatter = logging.Formatter(
        "%(asctime)s - [%(threadName)s] - %(name)s - %(levelname)s - %(module)s:%(funcName)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_name = os.path.join(log_dir, f"source_diff_analyzer_{datetime.now().strftime('%Y%m%d')}.log")

    console = logging.StreamHandler()
    console.setLevel(logging.ERROR)
    console.setFormatter(
        _ConsoleFormatter(
            "%(asctime)s - %(levelname)s - %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    try:
        file_handler = logging.FileHandler(file_name, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception:
        pass
    logger.addHandler(console)
    return logger


def get_logger(module_name: str | None = None) -> logging.Logger:
    setup_logger()
    name = f"{_LOGGER_NAME}.{module_name}" if module_name else _LOGGER_NAME
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = True
    return logger
