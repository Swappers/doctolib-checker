# doctolib_checker.py
#
# Env-only Doctolib checker with:
# - strict required env vars
# - optional Playwright discovery from FRONTEND_URL (via doctolib_discovery.py)
# - URL sanitization (removes start_date/end_date/limit even if present)
# - console logging (configurable via LOG_LEVEL)
# - optional Pushover notifications (PUSHOVER_API_TOKEN / PUSHOVER_USER_KEY)
#
# Required env:
#   RUN_IN_LOOP (true/false)
#   INTERVAL_IN_SECONDS (int)
#   ALIVE_CHECK (true/false)
#   HOUR_OF_ALIVE_CHECK (int, 0-23)
#   START_DATE (yyyy-mm-dd)          # currently informational; API URL is used as-is
#   LIMIT_DATE (yyyy-mm-dd)
#   LIMIT (int)                      # currently informational; API URL is used as-is
#   URL (availabilities.json URL) OR FRONTEND_URL (booking URL)
#
# Optional env:
#   LOG_LEVEL (DEBUG/INFO/WARNING/ERROR) default INFO
#   PUSHOVER_API_TOKEN
#   PUSHOVER_USER_KEY
#   FRONTEND_URL  (if set, will try to discover the availabilities.json URL)
#   DISCOVERY_HEADLESS (true/false) default true
#   DISCOVERY_TIMEOUT_MS (int) default 30000
#   DISCOVERY_WAIT_AFTER_LOAD_MS (int) default 3000

from __future__ import annotations

import datetime
import http.client
import json
import logging
import os
import sys
import time
import urllib.parse
import urllib.request
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse


# =========================
# LOGGING
# =========================

def setup_logging() -> None:
    level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


logger = logging.getLogger("doctolib_checker")


# =========================
# ENV HELPERS
# =========================

def require_env(name: str, cast=str):
    value = os.getenv(name)
    if value is None:
        raise SystemExit(f"ERROR: missing required env var {name}")
    try:
        return cast(value)
    except ValueError:
        raise SystemExit(f"ERROR: invalid value for {name}: {value}")


def env_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "y", "on")


def env_int(name: str) -> int:
    return require_env(name, int)


def env_bool_required(name: str) -> bool:
    return require_env(name, env_bool)


def env_int_default(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None:
        return default
    try:
        return int(v)
    except ValueError:
        raise SystemExit(f"ERROR: invalid int for {name}: {v}")


def env_bool_default(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return env_bool(v)


# =========================
# URL SANITIZATION
# =========================

FORBIDDEN_QUERY_PARAMS = {"start_date", "end_date", "limit"}


def sanitize_doctolib_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)

    for forbidden in FORBIDDEN_QUERY_PARAMS:
        query.pop(forbidden, None)

    clean_query = urlencode(query, doseq=True)

    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", clean_query, ""))


# =========================
# OPTIONAL PUSHOVER
# =========================

PUSHOVER_API_TOKEN = os.getenv("PUSHOVER_API_TOKEN")
PUSHOVER_USER_KEY = os.getenv("PUSHOVER_USER_KEY")
PUSHOVER_ENABLED = bool(PUSHOVER_API_TOKEN and PUSHOVER_USER_KEY)


def send_pushover_notification(message: str) -> None:
    if not PUSHOVER_ENABLED:
        logger.debug("Pushover disabled (missing PUSHOVER_API_TOKEN/PUSHOVER_USER_KEY).")
        return

    try:
        conn = http.client.HTTPSConnection("api.pushover.net:443", timeout=10)
        conn.request(
            "POST",
            "/1/messages.json",
            urllib.parse.urlencode(
                {
                    "token": PUSHOVER_API_TOKEN,
                    "user": PUSHOVER_USER_KEY,
                    "message": message,
                }
            ),
            {"Content-type": "application/x-www-form-urlencoded"},
        )
        resp = conn.getresponse()
        _ = resp.read()
        logger.info("Pushover notification sent (status=%s).", resp.status)
    except Exception as e:
        logger.error("Failed to send Pushover notification: %s", e)


# =========================
# BUSINESS LOGIC
# =========================

def format_string_to_date(date_str: str) -> str:
    # input: 2024-11-07T11:20:00.000+01:00
    return str(datetime.datetime.strptime(date_str[:-10], "%Y-%m-%dT%H:%M:%S"))


def get_closest_available_time_slot(json_data: dict, limit_date: str) -> str:
    for slot in json_data.get("availabilities", []):
        slots = slot.get("slots") or []
        if not slots:
            continue

        if datetime.datetime.strptime(
            slot["date"][:10], "%Y-%m-%d"
        ) <= datetime.datetime.strptime(limit_date, "%Y-%m-%d"):
            return slots[0]

    return ""


def fetch_availabilities(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "Magic Browser"})
    with urllib.request.urlopen(req, timeout=20) as con:
        return json.loads(con.read())


# =========================
# URL DISCOVERY (OPTIONAL)
# =========================

def resolve_api_url() -> str:
    """
    If FRONTEND_URL is set, attempt to discover the availabilities.json URL using Playwright.
    Otherwise use URL env var directly.
    In both cases, sanitize to remove start_date/end_date/limit.
    """
    frontend_url = os.getenv("FRONTEND_URL")

    if frontend_url:
        headless = env_bool_default("DISCOVERY_HEADLESS", True)
        timeout_ms = env_int_default("DISCOVERY_TIMEOUT_MS", 30_000)
        wait_after_load_ms = env_int_default("DISCOVERY_WAIT_AFTER_LOAD_MS", 3_000)

        logger.info("FRONTEND_URL provided, attempting discovery via Playwright.")
        logger.info("Discovery settings: headless=%s timeout_ms=%s wait_after_load_ms=%s",
                    headless, timeout_ms, wait_after_load_ms)

        try:
            from doctolib_discovery import discover_availabilities_json_url
        except Exception as e:
            raise SystemExit(
                f"ERROR: FRONTEND_URL is set but doctolib_discovery.py is not available/importable: {e}"
            )

        res = discover_availabilities_json_url(
            frontend_url,
            headless=headless,
            timeout_ms=timeout_ms,
            wait_after_load_ms=wait_after_load_ms,
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )

        if not res.sanitized_availabilities_url:
            logger.error("Discovery failed. Errors: %s", res.errors)
            raise SystemExit("ERROR: Could not discover availabilities.json URL from FRONTEND_URL")

        logger.info("Discovered sanitized availabilities URL: %s", res.sanitized_availabilities_url)
        return res.sanitized_availabilities_url

    raw_url = require_env("URL")
    sanitized = sanitize_doctolib_url(raw_url)
    if sanitized != raw_url:
        logger.info("Sanitized URL (removed start_date/end_date/limit).")
        logger.debug("Raw URL: %s", raw_url)
        logger.debug("Sanitized URL: %s", sanitized)
    return sanitized


# =========================
# MAIN
# =========================

def main() -> None:
    setup_logging()

    # Required configuration
    run_in_loop = env_bool_required("RUN_IN_LOOP")
    interval_in_seconds = env_int("INTERVAL_IN_SECONDS")

    alive_check = env_bool_required("ALIVE_CHECK")
    hour_of_alive_check = env_int("HOUR_OF_ALIVE_CHECK")

    start_date = require_env("START_DATE")
    limit_date = require_env("LIMIT_DATE")
    limit_days = env_int("LIMIT")

    # Basic validation
    try:
        datetime.datetime.strptime(start_date, "%Y-%m-%d")
        datetime.datetime.strptime(limit_date, "%Y-%m-%d")
    except ValueError:
        raise SystemExit("ERROR: START_DATE and LIMIT_DATE must be in yyyy-mm-dd format")

    if not (0 <= hour_of_alive_check <= 23):
        raise SystemExit("ERROR: HOUR_OF_ALIVE_CHECK must be between 0 and 23")

    if interval_in_seconds < 1:
        raise SystemExit("ERROR: INTERVAL_IN_SECONDS must be >= 1")

    if limit_days < 1:
        raise SystemExit("ERROR: LIMIT must be >= 1")

    url = resolve_api_url()

    logger.info("Starting doctolib-checker")
    logger.info("RUN_IN_LOOP=%s INTERVAL_IN_SECONDS=%s", run_in_loop, interval_in_seconds)
    logger.info("ALIVE_CHECK=%s HOUR_OF_ALIVE_CHECK=%s", alive_check, hour_of_alive_check)
    logger.info("START_DATE=%s LIMIT_DATE=%s LIMIT=%s", start_date, limit_date, limit_days)
    logger.info("API URL=%s", url)
    logger.info("Pushover enabled=%s", PUSHOVER_ENABLED)

    last_alive_day: str | None = None  # prevent multiple alive notifications within same day (minute=0 can still run multiple loops)

    while True:
        try:
            json_data = fetch_availabilities(url)
            total = json_data.get("total", 0)
            next_slot = json_data.get("next_slot")

            logger.debug("Fetched availability payload keys: %s", list(json_data.keys()))
            logger.info("total=%s next_slot=%s", total, next_slot)

            # Case 1: total slots > 0, check closest slot within LIMIT_DATE
            if total > 0:
                closest_slot = get_closest_available_time_slot(json_data, limit_date)
                if closest_slot:
                    msg = (
                        f"New appointment available within {limit_days} days\n"
                        f"Total: {total}\n"
                        f"Earliest (<= LIMIT_DATE): {format_string_to_date(closest_slot)}"
                    )
                    logger.warning("Match found (closest within LIMIT_DATE): %s", closest_slot)
                    send_pushover_notification(msg)
                else:
                    logger.info("Slots exist but none <= LIMIT_DATE.")

            # Case 2: total == 0 but next_slot exists and is <= LIMIT_DATE
            elif next_slot:
                try:
                    if datetime.datetime.strptime(
                        next_slot[:10], "%Y-%m-%d"
                    ) <= datetime.datetime.strptime(limit_date, "%Y-%m-%d"):
                        msg = (
                            "New appointment available within your limit date\n"
                            f"Earliest: {format_string_to_date(next_slot)}"
                        )
                        logger.warning("Match found (next_slot within LIMIT_DATE): %s", next_slot)
                        send_pushover_notification(msg)
                    else:
                        logger.info("No match: next_slot is after LIMIT_DATE.")
                except Exception:
                    logger.debug("Could not parse next_slot: %s", next_slot)

            # Alive check (once per day at exact hour:00)
            now = datetime.datetime.now()
            day_key = now.strftime("%Y-%m-%d")
            if alive_check and now.hour == hour_of_alive_check and now.minute == 0:
                if last_alive_day != day_key:
                    last_alive_day = day_key
                    logger.info("Alive check triggered for day %s", day_key)
                    send_pushover_notification(
                        f"Doctolib checker alive\nLimit date: {limit_date}"
                    )

            if run_in_loop:
                time.sleep(interval_in_seconds)
            else:
                logger.info("RUN_IN_LOOP=false, exiting after one run.")
                break

        except Exception as e:
            logger.exception("Runtime error: %s", e)
            send_pushover_notification(f"Doctolib checker error: {e}")

            # If not looping, fail fast so CI/containers can detect non-zero exit
            if not run_in_loop:
                raise


if __name__ == "__main__":
    main()
