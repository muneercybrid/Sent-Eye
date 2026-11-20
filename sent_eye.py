#!/usr/bin/env python3
"""
Sent-Eye: OSINT tool for image intelligence gathering.

Usage:
    python sent_eye.py <path-to-image> [--output report.json] [--html report.html] [--pretty]
    python sent_eye.py <path-to-image> --analyze-faces --acknowledge-consent [--face-db DIR]
"""
import argparse
import asyncio
import json
import os
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
    parser.add_argument("--html", help="Write an HTML report to this file.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner.")
    parser.add_argument(
        "--acknowledge-consent",
        action="store_true",
        help="Confirm you have the right to analyze this image.",
    )
    parser.add_argument(
        "--analyze-faces",
        action="store_true",
        help="Enable facial analysis. Requires --acknowledge-consent.",
    )
    parser.add_argument(
        "--face-db",
        metavar="DIR",
        help="Directory of reference face images for matching.",
    )
    args = parser.parse_args()

    if not args.no_banner:
        print(BANNER, file=sys.stderr)

    if not args.acknowledge_consent:
        print(
            "WARNING: Only analyze images you own or have permission to investigate.",
            file=sys.stderr,
        )

    # Face analysis is gated behind two independent confirmations.
    if args.analyze_faces and not args.acknowledge_consent:
        print(
            "ERROR: --analyze-faces requires --acknowledge-consent.\n"
            "       Face analysis is only permitted on images you own or "
            "have explicit written permission to analyze.",
            file=sys.stderr,
        )
        return 3

    if args.analyze_faces:
        os.environ["SENT_EYE_ENABLE_FACES"] = "1"

    if args.face_db:
        if not os.path.isdir(args.face_db):
            print(
                f"ERROR: --face-db directory not found: {args.face_db}",
                file=sys.stderr,
            )
            return 4
        os.environ["SENT_EYE_FACE_DB"] = args.face_db

    try:
        runner = SentEyeRunner(args.image)
        report = asyncio.run(runner.run_all())
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        output = json.dumps(report, indent=2 if args.pretty else None, default=str)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"JSON report written to {args.output}", file=sys.stderr)
    elif not args.html:
        print(json.dumps(report, indent=2 if args.pretty else None, default=str))

    if args.html:
        from backend.exporters.html_report import HTMLReporter
        html_content = HTMLReporter(report).render()
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_content)
        print(f"HTML report written to {args.html}", file=sys.stderr)

    return 0

if __name__ == "__main__":
    sys.exit(main())
