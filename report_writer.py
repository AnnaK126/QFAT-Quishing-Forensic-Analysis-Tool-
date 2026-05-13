"""
CSV report writer for QFAT

Writes CSV report with one row per email, including metadata, QR detection results, VT stats for URLs and files, and detection gap demonstration.
CSV_HEADERS defines the columns in the report, and must be kept consistent with the keys used in row dicts.
For email with no QR codes, one row is written with VT file stats marked n/a.
Designed for incremental output: rows are written as each email completes, so a crash mid-run doesn't lose prior results, but may cause loss of data for emails not yet processed.

Functions:
- initialise_report(output_path): creates CSV file, writes header row
- append_row(output_path, row_dict): appends one row to CSV, keys in row_dict must correspond to CSV_HEADERS

VT stats functions return dicts with keys malicious, harmless, undetected, total_engines, verdict, and cached (for files).
If an error occurs during VT submission or polling, the dict will contain a single key 'error' with a string message.
"""

import csv
from pathlib import Path

CSV_HEADERS = [
    # Email info
    'eml_filename',
    'message_id',
    'date_received',
    'from_address',
    'to_address',
    'subject',

    # Forensic integrity
    'tool_version',
    'eml_sha256',
    'qr_image_sha256',

    # QR detection result
    'qr_present',
    'qr_count',
    'decoded_urls',

    # VirusTotal URL analysis
    'url_vt_malicious',
    'url_vt_harmless',
    'url_vt_undetected',
    'url_vt_total_engines',
    'url_vt_verdict',

    # VirusTotal file analysis
    'file_vt_malicious',
    'file_vt_harmless',
    'file_vt_undetected',
    'file_vt_total_engines',
    'file_vt_verdict',
    'file_vt_cached',

    # Detection gap
    'detection_gap_demonstrated',

    # Timestamp
    'analysis_timestamp',
]

def initialise_report(output_path):
    """
    Create CSV file, write header row

    Args:
        output_path: path to CSV file to create
    If file already exists, it will be overwritten.

    Creates parent directories if they don't exist.
    """

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writeheader()

def append_row(output_path, row_dict):
    """
    Append one row to CSV file

    Args:
        output_path: path to CSV file to append to
        row_dict: dict with keys corresponding to CSV_HEADERS, values are the data for that row
    
    If output file doesn't exist, it will be created with header row.

   Keys in row_dict that are not in CSV_HEADERS will be ignored.
   If a key from CSV_HEADERS is missing in row_dict, the corresponding cell in the CSV will be left empty.

    Creates parent directories if they don't exist.
    """

    with open(output_path, 'a', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=CSV_HEADERS,
            extrasaction='ignore',
        )
        writer.writerow(row_dict)