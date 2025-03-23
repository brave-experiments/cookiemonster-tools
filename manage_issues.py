#!/usr/bin/env python3
"""
Manage GitHub issues based on website detection data from a JSONL file.
Creates/updates/closes/reopens issues based on detection status.
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

import github
from github import Github
from github.Issue import Issue
from github.Repository import Repository


# GitHub repository details
GITHUB_REPO = os.getenv("GITHUB_REPO")
if not GITHUB_REPO:
    sys.exit("Error: GITHUB_REPO environment variable not set")

# Environment variable name for GitHub token
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

# Issue title prefix to identify issues created by this script
ISSUE_PREFIX = "[Website Detection] "


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Manage GitHub issues based on website detection data"
    )
    parser.add_argument(
        "jsonl_file", help="Path to the JSONL file containing detection data"
    )
    return parser.parse_args()


def get_github_token() -> str:
    """Get GitHub token from environment variable."""
    token = os.environ.get(GITHUB_TOKEN_ENV)
    if not token:
        sys.exit(
            f"Error: GitHub token not found. Please set {GITHUB_TOKEN_ENV} environment variable."
        )
    return token


def connect_to_github(token: str) -> Github:
    """Connect to GitHub API."""
    return Github(token, per_page=100)


def get_repository(gh: Github) -> Repository:
    """Get the GitHub repository."""
    try:
        return gh.get_repo(GITHUB_REPO)
    except github.GithubException as e:
        sys.exit(f"Error accessing repository: {e}")


def fetch_all_issues(repo: Repository) -> Dict[str, Issue]:
    """Fetch all issues from the repository and index them by website URL."""
    issues = {}

    print("Fetching all issues from the repository...")
    for issue in repo.get_issues(state="all"):
        if issue.title.startswith(ISSUE_PREFIX):
            website_url = issue.title[len(ISSUE_PREFIX) :]
            issues[website_url] = issue

    print(f"Fetched {len(issues)} existing issues")
    return issues


def parse_jsonl(file_path: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parse the JSONL file and group entries by originalUrl.

    Each entry is expected to be a JSON array with three elements:
    [status_code, location, json_data]
    """
    website_data = defaultdict(list)

    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    # Parse the entry as [status_code, location, json_data]
                    entry = json.loads(line)
                    if len(entry) != 3:
                        print(f"Warning: Skipping malformed entry: {line[:100]}...")
                        continue

                    status_code, location, json_data_str = entry

                    if status_code != 200:
                        # Ignore failed API requests
                        continue

                    # Parse the JSON data string
                    json_data = json.loads(json_data_str)

                    if "originalUrl" not in json_data:
                        print(f"Warning: Entry missing originalUrl: {line[:100]}...")
                        continue

                    # Add location to the JSON data
                    json_data["location"] = location

                    # Group by originalUrl
                    website_data[json_data["originalUrl"]].append(json_data)

                except json.JSONDecodeError:
                    print(f"Warning: Could not parse JSON from line: {line[:180]}...")
                    print(line)
                except Exception as e:
                    print(f"Warning: Error processing line ({str(e)}): {line[:100]}...")

    except FileNotFoundError:
        sys.exit(f"Error: File {file_path} not found")
    except Exception as e:
        sys.exit(f"Error reading file: {str(e)}")

    print(f"Parsed data for {len(website_data)} unique websites")
    return website_data


def create_issue_body(website_data: List[Dict[str, Any]]) -> str:
    """Create the issue body markdown from website data."""
    body = f"## Crawl Report for {website_data[0]['originalUrl']}\n\n"

    # Sort entries by timestamp
    sorted_data = sorted(website_data, key=lambda x: x.get("timestamp", 0))

    # Add latest detection information
    latest = sorted_data[-1]
    body += "### Latest Detection\n"
    body += f"- URL: {latest.get('url', 'N/A')}\n"
    body += f"- Timestamp: {datetime.fromtimestamp(latest.get('timestamp', 0) / 1000).strftime('%Y-%m-%d %H:%M:%S')}\n"
    body += f"- Identified: {latest.get('identified', False)}\n"
    body += f"- Scroll Blocked: {latest.get('scrollBlocked', False)}\n"

    if "scriptSources" in latest and latest["scriptSources"]:
        body += "- Script Sources:\n"
        for source in latest["scriptSources"]:
            body += f"  - {source}\n"

    if "classifiersUsed" in latest and latest["classifiersUsed"]:
        body += f"- Classifiers Used: {', '.join(latest['classifiersUsed'])}\n"

    # Add crawl results
    if len(sorted_data) > 1:
        body += "\n### Crawl Results\n"

        for i, data in enumerate(reversed(sorted_data)):
            if i >= 5:  # Limit to last 5 detections to keep issue size manageable
                body += f"\n... {len(sorted_data) - 5} more detections ...\n"
                break

            location = data.get("location", "")
            location_info = f" via {location}" if location else " (direct)"

            body += f"\n**Detection {i + 1}**{location_info} - {datetime.fromtimestamp(data.get('timestamp', 0) / 1000).strftime('%Y-%m-%d %H:%M:%S')}\n"
            body += f"- Identified: {data.get('identified', False)}\n"
            body += f"- Scroll Blocked: {data.get('scrollBlocked', False)}\n"

    return body


def has_detection(website_data: List[Dict[str, Any]]) -> Tuple[bool, bool]:
    """Check if any entry for the website has a detection or scroll blocking.

    Returns:
        Tuple of (has_detection, is_scroll_blocked)
    """
    has_detection = any(data.get("identified", False) for data in website_data)
    is_scroll_blocked = any(data.get("scrollBlocked", False) for data in website_data)
    return has_detection, is_scroll_blocked


def manage_issues(
    repo: Repository,
    existing_issues: Dict[str, Issue],
    website_data: Dict[str, List[Dict[str, Any]]],
):
    """Manage GitHub issues based on website detection data."""
    created = 0
    updated = 0
    closed = 0
    reopened = 0

    for url, data_list in website_data.items():
        issue_title = f"{ISSUE_PREFIX}{url}"
        detection_found, is_scroll_blocked = has_detection(data_list)
        existing_issue = existing_issues.get(url)

        if existing_issue:
            # Get current labels excluding our managed labels
            current_labels = [
                label.name
                for label in existing_issue.labels
                if label.name not in ["scrollblocking", "cookie notice"]
            ]

            # Add managed labels if needed
            if is_scroll_blocked:
                current_labels.append("scrollblocking")
            if detection_found:
                current_labels.append("cookie notice")

            # Reopen issue if it's closed and has a detection or scroll blocking
            if existing_issue.state == "closed" and (
                detection_found or is_scroll_blocked
            ):
                # Reopen issue
                existing_issue.edit(
                    state="open",
                    body=create_issue_body(data_list),
                    labels=current_labels,
                )
                print(f"Reopened issue for {url}")
                reopened += 1

            # Update open issue if it has a detection or scroll blocking
            elif existing_issue.state == "open" and (
                detection_found or is_scroll_blocked
            ):
                # Update open issue
                existing_issue.edit(
                    body=create_issue_body(data_list), labels=current_labels
                )
                print(f"Updated issue for {url}")
                updated += 1

            elif existing_issue.state == "open" and not (
                detection_found or is_scroll_blocked
            ):
                # Close issue
                existing_issue.edit(state="closed")
                print(f"Closed issue for {url}")
                closed += 1

        elif detection_found:
            # Create new issue
            issue_body = create_issue_body(data_list)
            labels = []
            if is_scroll_blocked:
                labels.append("scrollblocking")
            if detection_found:
                labels.append("cookie notice")
            repo.create_issue(title=issue_title, body=issue_body, labels=labels)
            print(f"Created issue for {url}")
            created += 1

    print(f"\nSummary:")
    print(f"- Created: {created} issues")
    print(f"- Updated: {updated} issues")
    print(f"- Closed: {closed} issues")
    print(f"- Reopened: {reopened} issues")


def main():
    """Main function."""
    args = parse_args()
    token = get_github_token()

    # Connect to GitHub
    gh = connect_to_github(token)
    repo = get_repository(gh)

    # Fetch existing issues
    existing_issues = fetch_all_issues(repo)

    # Parse JSONL file
    website_data = parse_jsonl(args.jsonl_file)

    # Manage issues
    manage_issues(repo, existing_issues, website_data)


if __name__ == "__main__":
    main()
