#!/usr/bin/env python3

import argparse
import csv
import itertools
import json
import math
import os
import random
import signal
import sys
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from json.decoder import JSONDecodeError

import requests
from requests.adapters import HTTPAdapter
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)
from urllib3.util.retry import Retry

MAXIMUM_CONCURRENCY = 30

# Initialize global resources
output_file = None
executor = None
start_time = time.time()

# Thread-local storage for custom thread IDs and sessions
thread_local = threading.local()
# For debugging, we want sequential thread IDs
thread_id_counter = itertools.count(1)  # Start IDs at 1


def get_thread_id():
    if not hasattr(thread_local, "id"):
        # Assign a new ID the first time this thread runs
        thread_local.id = next(thread_id_counter)
    return thread_local.id


def get_session():
    """Get or create a requests session for the current thread."""
    if not hasattr(thread_local, "session"):
        # Configure retry strategy - include POST in allowed methods
        retry_strategy = Retry(
            total=5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=[
                "HEAD",
                "GET",
                "OPTIONS",
                "POST",
            ],  # In older versions use method_whitelist
            backoff_factor=5,
            backoff_jitter=1,
            respect_retry_after_header=True,
            raise_on_status=False,  # Don't raise exceptions on status codes in forcelist
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)

        # Create a session and mount the adapter
        session = requests.Session()
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        thread_local.session = session
    return thread_local.session


# Argument parsing
parser = argparse.ArgumentParser(description="Make requests to Cookiecrumbler API")
parser.add_argument(
    "-i", "--input-file", dest="input", required=True, help="Path to the input file"
)
parser.add_argument(
    "-o", "--output-file", dest="output", required=True, help="Path to the output file"
)
parser.add_argument(
    "-s",
    "--skip-lines",
    dest="skip_lines",
    type=int,
    default=0,
    help="Rows to skip from input CSV file",
)
parser.add_argument(
    "-v",
    "--skip-vpn-check",
    "--skip-auth-check",
    action="store_true",
    dest="skip_auth",
    help="Skip auth check",
)
parser.add_argument(
    "-p",
    "--parallel",
    dest="parallel",
    action="store_true",
    help="Enable parallel crawling",
)
args = parser.parse_args()

BASE_URL = "https://cookiecrumbler.brave.com"

API_KEY = os.getenv("API_KEY")


def ramp_up_delay(thread_id):
    # increment thread limit by 3 every 90 seconds
    max_active_threads = (
        min(MAXIMUM_CONCURRENCY, math.ceil((time.time() - start_time) / 120)) * 3
    )
    if MAXIMUM_CONCURRENCY > thread_id > max_active_threads:
        time.sleep(60 + random.randint(0, 10))


# Signal handling for graceful termination
def cleanup(signum=None, frame=None):
    """Handle cleanup on script termination."""
    print("\nTermination signal received. Cleaning up...")
    # Close the output file if open
    if output_file and not output_file.closed:
        output_file.close()
        print("Output file closed.")
    # Shut down the ThreadPoolExecutor gracefully
    if executor:
        executor.shutdown(wait=False)  # Stop accepting new tasks immediately
        print("Executor shut down.")
    sys.exit(0)  # Exit the program


# Register signal handlers
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)


def check_auth():
    try:
        session = get_session()
        response = session.get(BASE_URL, headers={"API-Key": API_KEY}, timeout=10)
        return response.status_code != 403
    except requests.RequestException as e:
        print(f"Auth/VPN check failed: {e}")
        return False


# Retry unexpected "requests" errors
@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=60),
    retry=retry_if_exception_type(requests.exceptions.RequestException),
)
def post_request_with_retry(url, location):
    endpoint = f"{BASE_URL}/check"
    payload = {
        "url": url,
        "adblockLists": {
            "adcocjohghhfpidemphmcmlmhnfgikei": True,
            "bfpgedeaaibpoidldhjcknekahbikncb": True,
            "cdbbhgbmjhfnhnmgeddbliobbofkgdhe": True,
            "eaokkjgnlhceblfhbhpeoebmfldocmnc": True,
        },
        "location": location,
        "screenshot": False,
    }
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["API-Key"] = API_KEY

    # Get the thread's session
    session = get_session()
    response = session.post(endpoint, json=payload, headers=headers, timeout=120)
    return response.status_code, response.text


def check_url(output_file, url, location, lock=None):
    # Get the custom thread ID for debugging
    thread_id = get_thread_id()
    ramp_up_delay(thread_id)

    status_code, response_body = post_request_with_retry(url, location)
    error, identified = None, False

    if status_code is None:
        print_message = (
            f"failed for {url} ({location}): {response_body} [Thread: {thread_id}]"
        )
    else:
        try:
            response_json = json.loads(response_body)
            error = response_json.get("error")
            identified = response_json.get("identified", False)
        except (JSONDecodeError, TypeError) as e:
            error = str(e)
        finally:
            if error:
                print_message = (
                    f"failed for {url} ({location}): {error} [Thread: {thread_id}]"
                )
            elif identified:
                print_message = (
                    f"identified for {url} ({location})! [Thread: {thread_id}]"
                )
            else:
                print_message = f"processed {url} ({location}) without identification [Thread: {thread_id}]"

    # Check if the URL should be ignored in the output.
    log_data = [status_code, location, response_body]

    log_entry = json.dumps(log_data)

    if lock:
        with lock:
            print(print_message)
            output_file.write(log_entry + "\n")
            output_file.flush()
    else:
        print(print_message)
        output_file.write(log_entry + "\n")
        output_file.flush()


def crawl(output_file, reader, parallel):
    output_lock = threading.Lock() if parallel else None

    def schedule(url, location):
        if parallel:
            executor.submit(check_url, output_file, url, location, output_lock)
        else:
            check_url(output_file, url, location)

    if parallel:
        executor = ThreadPoolExecutor(max_workers=MAXIMUM_CONCURRENCY)
        with executor:
            for row in reader:
                _, sitename = row
                url = f"https://{sitename}"
                schedule(url, "")
                schedule(url, "bg.stealthtunnel.net")
    else:
        for row in reader:
            _, sitename = row
            url = f"https://{sitename}"
            schedule(url, "")
            schedule(url, "bg.stealthtunnel.net")


if __name__ == "__main__":
    if not os.path.isfile(args.input):
        print(f"Error: Input file '{args.input}' does not exist.", file=sys.stderr)
        sys.exit(1)

    try:
        output_file = open(args.output, "a")
        with open(args.input, newline="") as csvfile:
            reader = csv.reader(csvfile)
            if not args.skip_auth and not check_auth():
                print("You must be connected to the VPN. Use -v to skip this check.")
                sys.exit(1)
            # Skip rows
            for _ in range(args.skip_lines):
                next(reader, None)
            crawl(output_file, reader, args.parallel)

    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Exiting...")
        cleanup()  # Call cleanup explicitly
    except Exception as e:
        print(f"An error occurred: {e}")
        print(traceback.format_exc())
    finally:
        # Ensure the file is closed even on unexpected errors
        if output_file and not output_file.closed:
            output_file.close()
            print("Output file closed.")
