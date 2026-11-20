# Sent-Eye

A modular OSINT tool for image intelligence gathering.

## Features

- Metadata Extraction: EXIF, GPS, and file metadata via ExifTool.
- (Coming soon) Reverse Image Search, Facial Recognition, Social Media Enrichment, Geolocation.

## Requirements

- Python 3.10+
- ExifTool (`sudo apt install libimage-exiftool-perl`)

## Setup

    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt

## Usage

    python sent_eye.py path/to/image.jpg --pretty

Options:

- `-o, --output FILE` — write the JSON report to a file.
- `--pretty` — pretty-print the JSON.
- `--no-banner` — suppress the ASCII banner.
- `--acknowledge-consent` — confirm you have the right to analyze the image.

## Ethics

Only analyze images you own or have explicit permission to investigate.
Respect platform ToS and privacy laws.

## Troubleshooting

### `ModuleNotFoundError: No module named 'pkg_resources'`

setuptools 82.0.0 (Feb 2026) removed `pkg_resources`. `face_recognition_models`
0.3.0 still imports it. Sent-Eye installs a compatibility shim
(`backend/compat.py`) at startup, so running via `sent_eye.py` works with
any setuptools version. If you need `import face_recognition` to work
outside Sent-Eye, run:

    pip install "setuptools<82"
