"""
QFAT main file

Run the full pipeline on all .eml files in the input folder, write results to CSV.

Designed for incremental output: rows are written as each email completes, so a crash mid-run doesn't lose prior results.

Run from the QFAT project root with the venv active:
    python main.py
"""

from datetime import datetime, timezone
from pathlib import Path

import config
import email_parser
import qr_extractor
import virustotal_client
import report_writer
import evidence

def _verdict_from_stats(stats):
    """
    Determine the overall verdict based on analysis stats
    'malicious' if any engine flagged malicious or suspicious
    'clean' if engines analysed and none flagged
    'error' if the stats dict contains an error

    Returns: 'malicious', 'clean', or 'error'
    """
    if 'error' in stats:
        return 'error'
    flagged = stats.get('malicious', 0) + stats.get('suspicious', 0)
    return 'malicious' if flagged > 0 else 'clean'

def _process_one_email(eml_path):
    """
    Process a single .eml file and return the analysis results

    Steps:
    parse email and extract metadata, attachments, inline images
    decode QR codes from attachments and inline images
    submit decoded URLs and file payloads to VirusTotal
    compile results into a list of CSV row dicts (one per QR code)
    Emails with no QR codes return a single row with VT fields marked 'n/a'.
    Emails with multiple QR codes (e.g. nested QR codes) return one row per QR allowing each URL to be independently analysed and recorded.

    Returns: list of dicts, each dict representing a CSV row
    """

    eml_path = Path(eml_path)
    eml_basename = eml_path.stem
    eml_sha256 = evidence.sha256_file(eml_path)
    evidence_dir = config.EVIDENCE_DIR / eml_basename

    evidence.audit_log(
        config.AUDIT_LOG,
        action='begin_processing',
        eml_hash=eml_sha256,
        extra=f'file={eml_path.name}',
    )

    parsed = email_parser.parse_eml(eml_path)
    metadata = parsed['metadata']

    # Common metadata applied to every row from  email
    base_row = {
        'eml_filename': metadata['filename'],
        'message_id': metadata['message_id'],
        'date_received': metadata['date'],
        'from_address': metadata['from'],
        'to_address': metadata['to'],
        'subject': metadata['subject'],
        'tool_version': config.TOOL_VERSION,
        'eml_sha256': eml_sha256,
    }

    qr_findings = [] # stores (url, payload, content_type, label) tuples

    for filename, content_type, payload in parsed['attachments']:
        if content_type == 'application/pdf':
            urls = qr_extractor.extract_qrs_from_pdf_bytes(payload)
        else:
            urls = qr_extractor.extract_qrs_from_image_bytes(payload)
        for url in urls:
            qr_findings.append((url, payload, content_type, filename))

    for cid, content_type, payload in parsed['inline_images']:
        urls = qr_extractor.extract_qrs_from_image_bytes(payload)
        for url in urls:
            qr_findings.append((url, payload, content_type, f'inline:{cid}'))
    
    total_qrs = len(qr_findings)
    all_decoded = '; '.join(url for url, _, _, _ in qr_findings)

    # No QR codes found: 'no QR' row
    if total_qrs == 0:
        evidence.write_manifest(evidence_dir, {
            'tool_version': config.TOOL_VERSION,
            'processed_utc': evidence.utc_now_iso(),
            'eml_filename': metadata['filename'],
            'eml_sha256': eml_sha256,
            'qr_findings': [],
        })
        evidence.audit_log(
            config.AUDIT_LOG,
            action='no_qr_found',
            eml_hash=eml_sha256,
        )
        row = dict(base_row)
        row.update({
            'qr_present': False,
            'qr_count': 0,
            'decoded_urls': '',
            'analysis_timestamp': evidence.utc_now_iso(),
            'qr_image_sha256': 'n/a',
        })
        for k in (
            'url_vt_malicious', 'url_vt_harmless', 'url_vt_undetected', 'url_vt_total_engines', 'url_vt_verdict',
            'file_vt_malicious', 'file_vt_harmless', 'file_vt_undetected', 'file_vt_total_engines', 'file_vt_verdict', 'file_vt_cached',
            'detection_gap_demonstrated',
        ):
            row[k] = 'n/a'
        return [row]

    rows = []
    manifest_findings = []

    for index, (url, payload, content_type, label) in enumerate(qr_findings, start=1):
        # Save artefact and hash before any further processing
        artefact_filename, qr_sha256 = evidence.save_qr_artefact(
            evidence_dir, index, content_type, payload,
        )
        evidence.audit_log(
            config.AUDIT_LOG,
            action='qr_extracted',
            eml_hash=eml_sha256,
            qr_hash=qr_sha256,
            extra=f'index={index}, label={label} file={artefact_filename}',
        )

        print(f' QR {index}/{total_qrs}: {url}')
        print(f'    Submitting URL to VirusTotal...')
        url_stats = virustotal_client.submit_url(url)
    
        print(f'    Submitting file to VirusTotal ({label})...')
        file_stats = virustotal_client.submit_file(payload)
        evidence.audit_log(
            config.AUDIT_LOG,
            action='vt_submission_complete',
            eml_hash=eml_sha256,
            qr_hash=qr_sha256,
        )
    
        row = dict(base_row)
        row.update({
            'qr_present': True,
            'qr_count': total_qrs,
            'decoded_urls': all_decoded,      # full list on every row for context
            'analysis_timestamp': evidence.utc_now_iso(),
            'qr_image_sha256': qr_sha256,

            'url_vt_malicious': url_stats.get('malicious', 'error'),
            'url_vt_harmless': url_stats.get('harmless', 'error'),
            'url_vt_undetected': url_stats.get('undetected', 'error'),
            'url_vt_total_engines': url_stats.get('total_engines', 'error'),
            'url_vt_verdict': _verdict_from_stats(url_stats),

            'file_vt_malicious': file_stats.get('malicious', 'error'),
            'file_vt_harmless': file_stats.get('harmless', 'error'),
            'file_vt_undetected': file_stats.get('undetected', 'error'),
            'file_vt_total_engines': file_stats.get('total_engines', 'error'),
            'file_vt_verdict': _verdict_from_stats(file_stats),
            'file_vt_cached': file_stats.get('cached', 'n/a'),
        })

        url_flagged = isinstance(url_stats.get('malicious'), int) and url_stats['malicious'] > 0
        file_flagged = isinstance(file_stats.get('malicious'), int) and file_stats['malicious'] > 0
        row['detection_gap_demonstrated'] = url_flagged and not file_flagged

        rows.append(row)
        manifest_findings.append({
            'index': index,
            'label': label,
            'content_type': content_type,
            'artefact_file': artefact_filename,
            'artefact_sha256': qr_sha256,
            'decoded_url': url,
        })

    evidence.write_manifest(evidence_dir, {
        'tool_version': config.TOOL_VERSION,
        'processed_utc': evidence.utc_now_iso(),
        'eml_filename': metadata['filename'],
        'eml_sha256': eml_sha256,
        'qr_findings': manifest_findings,
    })
    evidence.audit_log(
        config.AUDIT_LOG,
        action='processing_complete',
        eml_hash=eml_sha256,
        extra=f'qr_count={total_qrs}',
    )

    return rows

def analyse_folder(folder_path, output_csv):
    """
    Process all .eml files in the input folder and write results to output CSV
    
    For each .eml file:
    call _process_one_email to get list of row dicts
    append rows to CSV using report_writer
    
    Parameters:
    folder_path: path to folder containing .eml files
    output_csv: path to output CSV file
        """

    folder = Path(folder_path)
    output_csv = Path(output_csv)

    eml_files = sorted(folder.glob('*.eml'))
    if not eml_files:
        print(f'No .eml files found in {folder}')
        return
    
    print(f'Found {len(eml_files)} .eml file(s) to process')
    print(f'Output CSV: {output_csv}')
    print(f'Evidence: {config.EVIDENCE_DIR}')
    print(f'Audit log: {config.AUDIT_LOG}\n')

    report_writer.initialise_report(output_csv)

    for i, eml_path in enumerate(eml_files, start=1):
        print(f'[{i}/{len(eml_files)}] {eml_path.name}')
        try:
            rows = _process_one_email(eml_path)
            for row in rows:
                report_writer.append_row(output_csv, row)
            print(f'  Logged {len(rows)} row(s).\n')
        except Exception as e:
            print(f'  ERROR: {e}\n')
            evidence.audit_log(
                config.AUDIT_LOG,
                action='processing_error',
                extra=f'file={eml_path.name} error="{e!r}"',
            )
        
    print(f'Done. Report written to {output_csv}')

if __name__ == '__main__':
    analyse_folder(config.INPUT_FOLDER, config.OUTPUT_CSV)