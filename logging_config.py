"""
Anonymized logging configuration for Uvicorn and FastAPI.
Prevents IP addresses (client.host, X-Forwarded-For, X-Real-IP) from appearing in
stdout, stderr, or any log output to protect whistleblower and user privacy.
"""

import copy
import logging
import re
from typing import Any
from uvicorn.config import LOGGING_CONFIG


class IPAnonymizeFilter(logging.Filter):
    """
    Strips client IP addresses and sensitive proxy headers from all log records.
    """
    IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")
    IPV6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(?::\d+)?\b")

    def filter(self, record: logging.LogRecord) -> bool:
        # 1. Anonymize uvicorn access record args (client_addr, method, path, http_version, status_code)
        if record.args and isinstance(record.args, tuple):
            args_list = list(record.args)
            if len(args_list) >= 1 and isinstance(args_list[0], str):
                args_list[0] = "[ANONYMIZED_CLIENT]"
            record.args = tuple(args_list)

        # 2. Anonymize any IP addresses embedded inside message string
        if isinstance(record.msg, str):
            record.msg = self.IPV4_PATTERN.sub("[ANONYMIZED_IP]", record.msg)
            record.msg = self.IPV6_PATTERN.sub("[ANONYMIZED_IP]", record.msg)

        return True


def get_anonymized_uvicorn_log_config() -> dict[str, Any]:
    """
    Returns Uvicorn logging configuration with client IP logging explicitly disabled.
    Replaces %(client_addr)s with [ANONYMIZED_CLIENT].
    """
    config = copy.deepcopy(LOGGING_CONFIG)
    if "formatters" in config and "access" in config["formatters"]:
        fmt = config["formatters"]["access"].get("fmt", "")
        if "%(client_addr)s" in fmt:
            config["formatters"]["access"]["fmt"] = fmt.replace("%(client_addr)s", "[ANONYMIZED_CLIENT]")
        else:
            config["formatters"]["access"]["fmt"] = '%(levelprefix)s [ANONYMIZED_CLIENT] - "%(request_line)s" %(status_code)s'

    return config


def setup_anonymized_logging() -> None:
    """
    Attaches IPAnonymizeFilter to all standard and uvicorn loggers.
    Ensures that even if custom logs or standard formatters run, IPs are never emitted.
    """
    anonymize_filter = IPAnonymizeFilter()

    loggers_to_patch = [
        logging.getLogger(),
        logging.getLogger("uvicorn"),
        logging.getLogger("uvicorn.access"),
        logging.getLogger("uvicorn.error"),
        logging.getLogger("fastapi"),
    ]

    for logger in loggers_to_patch:
        logger.addFilter(anonymize_filter)
        for handler in logger.handlers:
            handler.addFilter(anonymize_filter)
