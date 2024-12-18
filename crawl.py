#!/usr/bin/env python3

import requests
import csv
import argparse
import signal
import sys
import os

parser = argparse.ArgumentParser(description='Make requests to Cookiemonster API')
parser.add_argument('-i', '--input-file', dest='input', required=True, help='Path to the input file')
parser.add_argument('-o', '--output-file', dest='output', required=True, help='Path to the output file')
parser.add_argument('-s', '--skip', dest='skip', type=int, default=0, help='Rows to skip from input CSV file (default: 0)')
parser.add_argument('-c', '--skip-vpn-check', dest='skip_vpn', default=False, help='Skip check for company VPN before starting crawl (default: False)')
args = parser.parse_args()

BASE_URL = "https://cookiemonster.brave.com"

output_file = None

# Ensure file is closed properly even on interruption
def cleanup(signum=None, frame=None):
    if output_file and not output_file.closed:
        output_file.close()
    sys.exit(0)

# Signal handlers to handle termination
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

# Make sure we're on internal VPN
def check_vpn():
    try:
        response = requests.get(BASE_URL)
        return response.status_code != 403
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return False

# Call Cookiemonster API
def post_request(url, location):
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
    headers = {
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(endpoint, json=payload, headers=headers, timeout=120)
        status_code = response.status_code
        response_json = response.json()
        identified = response_json.get("identified", False)
        error = response_json.get("error")
        return url, status_code, identified, error
    except requests.Timeout:
        return url, None, False, "Request timed out"
    except requests.RequestException as e:
        return url, None, False, f"Request error: {str(e)}"

# Read input CSV with list of domains
# Read line by line, skipping rows if necessary
# Calls from both current (SF) and EU (Belgium) locations
def read_csv_make_requests(skip):
    # Check if on VPN, required for Cookiemonster
    if not args.skip_vpn and not check_vpn():
        print("You have to be on the internal company VPN!")
        return
    with open(args.input, newline='') as csvfile:
        print("Reading input file and doing crawl...")
        reader = csv.reader(csvfile)
        # Skip rows
        for _ in range(skip):
            next(reader, None)
        for row in reader:
            rank, sitename = row
            # We make a URL by appending the scheme to the domain
            url = f"https://{sitename}"
            # Crawl from both current (no proxy) and EU (Belgium) locations
            crawl_url(url, "")
            crawl_url(url, "bg.stealthtunnel.net")

# Write to both stdout and output file
def crawl_url(url, location):
    url, status_code, identified, error = post_request(url, location)
    region = "San Francisco" if location == "" else "Europe"
    log_entry = f"URL: {url}, Identified: {identified}, Status: {status_code}, Location: {region}, Error: {error}\n"
    print(log_entry, end='', flush=True)  # Print to console
    output_file.write(log_entry)  # Write to output file

if __name__ == "__main__":
    # Check if the input file exists
    if not os.path.isfile(args.input):
        print(f"Error: Input file '{args.input}' does not exist.", file=sys.stderr)
        sys.exit(1)
    # Open output file in append mode
    output_file = open(args.output, 'a')
    try:
        read_csv_make_requests(args.skip)
    finally:
        cleanup()  # Ensure cleanup is always called

