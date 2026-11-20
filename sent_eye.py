#!/usr/bin/env python3
"""
Sent-Eye: OSINT tool for image intelligence gathering.

Usage:
    python sent_eye.py <path-to-image> [--output report.json] [--pretty]
"""
import argparse
import asyncio
import json
import sys

from backend.core.runner import SentEyeRunner

BANNER = r"""
   _____            __     ______
  / ___/___  ____  / /_   / ____/_  __
  \__ \/ _ \/ __ \/ __/  / __/ / / / /
 ___/ /  __/ / / / /_   / /___/ /_/ /
/____/\___/_/ /_/\__/  /_____/\__, /
                             /____/
       OSINT Image Intelligence Tool
"""

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sent-Eye: analyze an image with OSINT modules."
    )
    parser.add_argument("image", help="Path to the image file to analyze.")
    parser.add_argument("-o", "--output", help="Write the JSON report to this file.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner.")
    parser.add_argument(
        "--acknowledge-consent",
        action="store_true",
        help="Confirm you have the right to analyze this image.",
    )
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER, file=sys.stderr)

    if not args.acknowledge_consent:
        print(
            "WARNING: Only analyze images you own or have permission to investigate.",
            file=sys.stderr,
        )

    try:
        runner = SentEyeRunner(args.image)
        report = asyncio.run(runner.run_all())
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 2

    output = json.dumps(report, indent=2 if args.pretty else None, default=str)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    return 0

if __name__ == "__main__":
    sys.exit(main())
