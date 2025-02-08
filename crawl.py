#!/usr/bin/env python3

import json
import requests
from json.decoder import JSONDecodeError
import csv
import argparse
import signal
import sys
import itertools
import traceback
import os
from concurrent.futures import ThreadPoolExecutor
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import threading

# Initialize global resources
output_file = None
executor = None

# Argument parsing
parser = argparse.ArgumentParser(description='Make requests to Cookiemonster API')
parser.add_argument('-i', '--input-file', dest='input', required=True, help='Path to the input file')
parser.add_argument('-o', '--output-file', dest='output', required=True, help='Path to the output file')
parser.add_argument('-s', '--skip-lines', dest='skip_lines', type=int, default=0, help='Rows to skip from input CSV file')
parser.add_argument('-v', '--skip-vpn-check', '--skip-auth-check', action='store_true', dest='skip_auth', help='Skip auth check')
parser.add_argument('-p', '--parallel', dest='parallel', action='store_true', help='Enable parallel crawling')
args = parser.parse_args()

BASE_URL = "https://cookiemonster.brave.com"

API_KEY = os.getenv('API_KEY')

# For debugging, we want sequential thread IDs
# Thread-local storage for custom thread IDs
thread_local = threading.local()
# Counter for assigning sequential thread IDs
thread_id_counter = itertools.count(1)  # Start IDs at 1
def get_thread_id():
    if not hasattr(thread_local, "id"):
        # Assign a new ID the first time this thread runs
        thread_local.id = next(thread_id_counter)
    return thread_local.id

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
        response = requests.get(BASE_URL, headers={'API-Key': API_KEY}, timeout=10)
        return response.status_code != 403
    except requests.RequestException as e:
        print(f"Auth/VPN check failed: {e}")
        return False

# Retry HTTP requests to the Cookiemonster API
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=60),
       retry=retry_if_exception_type(requests.exceptions.RequestException))
def post_request_with_retry(url, location):
    endpoint = f"{BASE_URL}/check"
    payload = {
        "url": url,
        "adblockLists": {
            "adcocjohghhfpidemphmcmlmhnfgikei": True,
            "bfpgedeaaibpoidldhjcknekahbikncb": True,
            "cdbbhgbmjhfnhnmgeddbliobbofkgdhe": True,
            "eaokkjgnlhceblfhbhpeoebmfldocmnc": True
        },
        "location": location,
        "screenshot": False
    }
    headers = {'Content-Type': 'application/json'}
    if API_KEY:
        headers['API-Key'] = API_KEY
    response = requests.post(endpoint, json=payload, headers=headers, timeout=120)
    return response.status_code, response.text

def check_url(output_file, url, location, lock=None):
    # Get the custom thread ID for debugging
    thread_id = get_thread_id()

    status_code, response_body = post_request_with_retry(url, location)
    error, identified = None, False

    if status_code is None:
        print_message = f"failed for {url} ({location}): {response_body} [Thread: {thread_id}]"
    else:
        try:
            response_json = json.loads(response_body)
            error = response_json.get("error")
            identified = response_json.get("identified", False)
        except (JSONDecodeError, TypeError) as e:
            error = str(e)
        finally:
            if error:
                print_message = f"failed for {url} ({location}): {error} [Thread: {thread_id}]"
            elif identified:
                print_message = f"identified for {url} ({location})! [Thread: {thread_id}]"
            else:
                print_message = f"processed {url} ({location}) without identification [Thread: {thread_id}]"

    log_entry = json.dumps([status_code, location, response_body])
    if lock:
        with lock:
            print(print_message)
            output_file.write(log_entry + '\n')
            output_file.flush()
    else:
        print(print_message)
        output_file.write(log_entry + '\n')
        output_file.flush()

def crawl(output_file, reader, parallel):
    output_lock = threading.Lock() if parallel else None

    def schedule(url, location):
        if parallel:
            executor.submit(check_url, output_file, url, location, output_lock)
        else:
            check_url(output_file, url, location)

    if parallel:
        executor = ThreadPoolExecutor(max_workers=10)
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
        output_file = open(args.output, 'a')
        with open(args.input, newline='') as csvfile:
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
