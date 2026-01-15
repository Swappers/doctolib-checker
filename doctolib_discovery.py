# doctolib_discovery.py
"""
Discover Doctolib API URL (availabilities.json) from a frontend booking URL using Playwright.

- Input: a "basic" Doctolib booking URL (frontend), e.g.
  https://www.doctolib.fr/.../booking/availabilities?...placeId=practice-...&motiveIds[]=...

- Output: logs to console + a dict containing:
  - raw_availabilities_url: the first availabilities.json URL seen
  - sanitized_availabilities_url: same URL but with start_date/end_date/limit removed
  - extracted: agenda_ids, practice_ids, visit_motive_ids (if present)
  - frontend: parsed details from the frontend URL

Usage (CLI):
  python doctolib_discovery.py "<FRONTEND_URL>"

Install:
  pip install playwright
  playwright install chromium
"""

from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError


# -----------------------
# Logging
# -----------------------

def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


# -----------------------
# URL helpers
# -----------------------

FORBIDDEN_QUERY_PARAMS = {"start_date", "end_date", "limit"}


def sanitize_doctolib_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)

    for forbidden in FORBIDDEN_QUERY_PARAMS:
        query.pop(forbidden, None)

    clean_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", clean_query, ""))


def extract_ids_from_availabilities_url(av_url: str) -> Dict[str, Any]:
    """
    Extract agenda_ids/practice_ids/visit_motive_ids from availabilities.json URL if present.
    """
    parsed = urlparse(av_url)
    q = parse_qs(parsed.query)

    def pick(name: str) -> Optional[str]:
        vals = q.get(name)
        if not vals:
            return None
        # doctolib often returns comma-separated ids as a single string
        return vals[0]

    return {
        "agenda_ids": pick("agenda_ids"),
        "practice_ids": pick("practice_ids"),
        "visit_motive_ids": pick("visit_motive_ids"),
    }


def parse_frontend_url(frontend_url: str) -> Dict[str, Any]:
    """
    Parse notable data from the frontend URL (best-effort).
    Example:
      placeId=practice-144984 -> practice_slug_id=144984 (not always same as practice_ids)
      motiveIds[]=211243 -> motive_ids=[211243]
    """
    p = urlparse(frontend_url)
    q = parse_qs(p.query)

    place_id = (q.get("placeId") or [None])[0]
    motive_ids = q.get("motiveIds[]") or q.get("motiveIds%5B%5D") or q.get("motiveIds") or []
    speciality_id = (q.get("specialityId") or [None])[0]
    telehealth = (q.get("telehealth") or [None])[0]

    practice_slug_id = None
    if place_id and place_id.startswith("practice-"):
        practice_slug_id = place_id.split("practice-", 1)[1]

    return {
        "path": p.path,
        "placeId": place_id,
        "practice_slug_id": practice_slug_id,
        "motiveIds": motive_ids,
        "specialityId": speciality_id,
        "telehealth": telehealth,
    }


# -----------------------
# Result model
# -----------------------

@dataclass
class DiscoveryResult:
    frontend_url: str
    frontend: Dict[str, Any]
    raw_availabilities_url: Optional[str]
    sanitized_availabilities_url: Optional[str]
    extracted: Dict[str, Any]
    duration_seconds: float
    errors: List[str]


# -----------------------
# Playwright discovery
# -----------------------

def discover_availabilities_json_url(
    frontend_url: str,
    *,
    headless: bool = True,
    timeout_ms: int = 30_000,
    wait_after_load_ms: int = 3_000,
    log_level: str = "INFO",
) -> DiscoveryResult:
    """
    Launches Chromium, loads the frontend URL, listens for network requests,
    and returns the first availabilities.json request URL observed.
    """
    setup_logging(log_level)
    logger = logging.getLogger("doctolib_discovery")

    start = time.time()
    errors: List[str] = []

    frontend_parsed = parse_frontend_url(frontend_url)
    logger.info("Frontend URL: %s", frontend_url)
    logger.info("Frontend parsed: %s", json.dumps(frontend_parsed, ensure_ascii=False))

    raw_av_url: Optional[str] = None
    sanitized_av_url: Optional[str] = None
    extracted: Dict[str, Any] = {"agenda_ids": None, "practice_ids": None, "visit_motive_ids": None}

    def on_request(request) -> None:
        nonlocal raw_av_url, sanitized_av_url, extracted
        url = request.url
        if "availabilities.json" in url and raw_av_url is None:
            raw_av_url = url
            sanitized_av_url = sanitize_doctolib_url(url)
            extracted = extract_ids_from_availabilities_url(sanitized_av_url)

            logger.info("Found availabilities.json request.")
            logger.info("raw_availabilities_url=%s", raw_av_url)
            logger.info("sanitized_availabilities_url=%s", sanitized_av_url)
            logger.info("extracted=%s", json.dumps(extracted, ensure_ascii=False))

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            context = browser.new_context(
            viewport={"width": 1280, "height": 800},
            user_agent=(
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"),
            )
            page = context.new_page()

            page.on("request", on_request)

            logger.info("Launching browser (headless=%s)...", headless)

            try:
                page.goto(frontend_url, wait_until="domcontentloaded", timeout=timeout_ms)
            except PlaywrightTimeoutError:
                msg = f"Timeout while loading page after {timeout_ms}ms"
                errors.append(msg)
                logger.error(msg)

            # Let the SPA do its XHR/fetch calls
            page.wait_for_timeout(wait_after_load_ms)

            # If not found yet, wait a bit longer for late requests
            if raw_av_url is None:
                logger.info("availabilities.json not seen yet; waiting extra...")
                page.wait_for_timeout(2_000)

            context.close()
            browser.close()

    except Exception as e:
        msg = f"Playwright error: {e}"
        errors.append(msg)
        logger.exception(msg)

    duration = time.time() - start

    if raw_av_url is None:
        msg = "No availabilities.json request captured. URL may be wrong, blocked, or requires interactions."
        errors.append(msg)
        logging.getLogger("doctolib_discovery").error(msg)

    return DiscoveryResult(
        frontend_url=frontend_url,
        frontend=frontend_parsed,
        raw_availabilities_url=raw_av_url,
        sanitized_availabilities_url=sanitized_av_url,
        extracted=extracted,
        duration_seconds=duration,
        errors=errors,
    )


# -----------------------
# CLI
# -----------------------

def main() -> None:
    if len(sys.argv) < 2:
        print('Usage: python doctolib_discovery.py "<FRONTEND_URL>"', file=sys.stderr)
        sys.exit(2)

    frontend_url = sys.argv[1]
    result = discover_availabilities_json_url(frontend_url)

    # Print a machine-readable JSON summary at the end
    print(json.dumps(asdict(result), ensure_ascii=False, indent=2))

    # Exit non-zero if discovery failed
    if result.raw_availabilities_url is None:
        sys.exit(1)


if __name__ == "__main__":
    main()
