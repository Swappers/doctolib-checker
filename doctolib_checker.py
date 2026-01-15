import datetime
import http.client
import json
import time
import urllib.request
import urllib.parse
import os
import sys
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

def require_env(name, cast=str):
    value = os.getenv(name)
    if value is None:
        print(f"ERROR: missing required env var {name}", file=sys.stderr)
        sys.exit(1)
    try:
        return cast(value)
    except ValueError:
        print(f"ERROR: invalid value for {name}: {value}", file=sys.stderr)
        sys.exit(1)

def env_bool(value: str) -> bool:
    return value.lower() in ("1", "true", "yes")

def sanitize_doctolib_url(raw_url: str) -> str:
    parsed = urlparse(raw_url)
    query = parse_qs(parsed.query)

    # paramètres interdits : toujours ignorés
    for forbidden in ("start_date", "end_date", "limit"):
        query.pop(forbidden, None)

    clean_query = urlencode(query, doseq=True)

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            clean_query,
            "",
        )
    )

RUN_IN_LOOP = require_env("RUN_IN_LOOP", env_bool)
INTERVAL_IN_SECONDS = require_env("INTERVAL_IN_SECONDS", int)

ALIVE_CHECK = require_env("ALIVE_CHECK", env_bool)
HOUR_OF_ALIVE_CHECK = require_env("HOUR_OF_ALIVE_CHECK", int)

START_DATE = require_env("START_DATE")
LIMIT_DATE = require_env("LIMIT_DATE")
LIMIT = require_env("LIMIT", int)

URL = require_env("URL")

PUSHOVER_API_TOKEN = os.getenv("PUSHOVER_API_TOKEN")
PUSHOVER_USER_KEY = os.getenv("PUSHOVER_USER_KEY")
PUSHOVER_ENABLED = PUSHOVER_API_TOKEN is not None and PUSHOVER_USER_KEY is not None


def send_pushover_notification(message: str):
    if not PUSHOVER_ENABLED:
        return

    conn = http.client.HTTPSConnection("api.pushover.net:443")
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
    conn.getresponse()

def get_closest_available_time_slot(json_data):
    for slot in json_data.get("availabilities", []):
        if not slot.get("slots"):
            continue

        if datetime.datetime.strptime(
            slot["date"][:10], "%Y-%m-%d"
        ) <= datetime.datetime.strptime(LIMIT_DATE, "%Y-%m-%d"):
            return slot["slots"][0]

    return ""

def format_string_to_date(date: str) -> str:
    # input: 2024-11-07T11:20:00.000+01:00
    return str(datetime.datetime.strptime(date[:-10], "%Y-%m-%dT%H:%M:%S"))

def main():
    print("Starting doctolib-checker")
    print(f"Using URL: {URL}")
    print(f"Limit date: {LIMIT_DATE}")

    while True:
        try:
            req = urllib.request.Request(URL, headers={"User-Agent": "Magic Browser"})
            with urllib.request.urlopen(req) as con:
                json_data = json.loads(con.read())

            # slots available in next LIMIT days
            if json_data.get("total", 0) > 0:
                closest_slot = get_closest_available_time_slot(json_data)
                if closest_slot:
                    send_pushover_notification(
                        f"New appointment available within {LIMIT} days\n"
                        f"Total: {json_data['total']}\n"
                        f"Earliest: {format_string_to_date(closest_slot)}"
                    )

            # next available slot before LIMIT_DATE
            elif "next_slot" in json_data and datetime.datetime.strptime(
                json_data["next_slot"][:10], "%Y-%m-%d"
            ) <= datetime.datetime.strptime(LIMIT_DATE, "%Y-%m-%d"):
                send_pushover_notification(
                    f"New appointment available\n"
                    f"Earliest: {format_string_to_date(json_data['next_slot'])}"
                )

            # alive check
            if (
                ALIVE_CHECK
                and datetime.datetime.now().hour == HOUR_OF_ALIVE_CHECK
                and datetime.datetime.now().minute == 0
            ):
                send_pushover_notification(
                    f"Doctolib checker alive\nLimit date: {LIMIT_DATE}"
                )

            if RUN_IN_LOOP:
                time.sleep(INTERVAL_IN_SECONDS)
            else:
                break

        except Exception as e:
            send_pushover_notification(f"Doctolib checker error: {e}")
            if not RUN_IN_LOOP:
                raise


if __name__ == "__main__":
    main()
