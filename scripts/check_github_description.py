#!/usr/bin/env python3
"""Check that the GitHub repository description does not contain outdated marketing claims.

Usage:
    python scripts/check_github_description.py [owner/repo]

The script queries the GitHub API for the repository description and fails if any of
the forbidden phrases are still present. A GITHUB_TOKEN is optional but raises the rate limit.
"""

import os
import re
import sys
import urllib.request
import urllib.error

DEFAULT_REPO = "rolanfreeman6-png/stealthlib"

FORBIDDEN_PHRASES = [
    "zero strings",
    "zero imports",
    "complete binary protection",
    "complete protection",
]

EXPECTED_PATTERNS = [
    r"windows",
    r"obfuscat",
    r"harden",
    r"string",
    r"api",
    r"peb",
]


def get_description(repo: str) -> str:
    url = f"https://api.github.com/repos/{repo}"
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "stealthlib-description-check"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            import json
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"[-] GitHub API error: {e.code} {e.reason}")
        try:
            print(e.read().decode("utf-8"))
        except Exception:
            pass
        sys.exit(2)
    except Exception as e:
        print(f"[-] Failed to query GitHub API: {e}")
        sys.exit(2)

    return data.get("description") or ""


def main() -> int:
    repo = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_REPO
    description = get_description(repo)
    print(f"[*] Repository: {repo}")
    print(f"[*] Description: {description!r}")

    lower = description.lower()
    errors = []

    for phrase in FORBIDDEN_PHRASES:
        if phrase in lower:
            errors.append(f"Forbidden phrase found: {phrase!r}")

    if not description.strip():
        errors.append("Repository description is empty.")
    elif not any(re.search(p, lower) for p in EXPECTED_PATTERNS):
        errors.append(
            "Description does not contain expected Windows/obfuscation/hardening keywords."
        )

    if errors:
        print("[-] Description check FAILED:")
        for e in errors:
            print(f"    - {e}")
        print("[i] Update the description in the GitHub repository settings to match the honest pre-release positioning.")
        return 1

    print("[+] Description check PASSED.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
