#!/usr/bin/env python3
"""Fail CI when a reachable commit was authored by an unapproved identity."""

from __future__ import annotations

import subprocess
import sys


ALLOWED_EMAILS = {"hankhantzaw16@gmail.com", "kaungkhantko26@users.noreply.github.com"}
ALLOWED_NOREPLY_SUFFIX = "+kaungkhantko26@users.noreply.github.com"


def main() -> int:
    output = subprocess.check_output(
        ["git", "log", "--format=%H%x09%an%x09%ae", "HEAD"], text=True
    )
    rejected = []
    for line in output.splitlines():
        commit, author, email = line.split("\t", 2)
        if email not in ALLOWED_EMAILS and not email.endswith(ALLOWED_NOREPLY_SUFFIX):
            rejected.append((commit[:12], author, email))

    if rejected:
        print("Unapproved commit authors detected:", file=sys.stderr)
        for commit, author, email in rejected:
            print(f"  {commit}  {author} <{email}>", file=sys.stderr)
        return 1

    print("Ownership check passed: every reachable commit belongs to kaungkhantko26.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
