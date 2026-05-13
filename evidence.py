"""
Evidence preservation for QFAT
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

def utc_now_iso():
    """Get the current UTC time in ISO 8601 format, second precision."""
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def sha256_bytes(data):
    """SHA256 hexdigest of raw bytes."""
    return hashlib.sha256(data).hexdigest()

def sha256_file(path):
    """Calculate the SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def _ext_for_content_type(content_type):
    """Map a content type to a file extension, defaulting to 'bin'."""
    return{
        'image/png': 'png',
        'image/jpeg': 'jpg',
        'image/gif': 'gif',
        'image/webp': 'webp',
        'application/pdf': 'pdf',
    }.get(content_type, 'bin')

def save_qr_artefact(evidence_dir, index, content_type, payload_bytes):
    """Save a QR artefact to the evidence directory and return its filename and SHA-256 hash.
    
    Artefact preserved as delivered without re-encoding, so saved file's hash matches bytes submitted to VirusTotal
    
    Args:
        evidence_dir (str or Path): Directory to save the artefact in.
        index (int): Index of the artefact for naming purposes.
        content_type (str): MIME type of the artefact, used to determine file extension.
        payload_bytes (bytes): The raw bytes of the artefact to be saved.
        
    Returns: (filename, sha256_hash)
    """
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    ext = _ext_for_content_type(content_type)
    filename = f'qr_{index}.{ext}'
    (evidence_dir / filename).write_bytes(payload_bytes)
    return filename, sha256_bytes(payload_bytes)

def write_manifest(evidence_dir, manifest_data):
    """Write the manifest data to a JSON file in the evidence directory."""
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = evidence_dir / 'manifest.json'
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest_data, f, indent=2)
    return manifest_path

def audit_log(log_path, action, eml_hash='', qr_hash='', extra=''):
    """
    Append an entry to the audit log.
    
    Format: <UTC ISO>\\t<action>\\teml=<hash>\\tqr=<hash>\\t<extra>
    Append only - do not modify existing entries to preserve integrity of the log.
    """
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = utc_now_iso()
    with open(log_path, 'a', encoding='utf-8') as f:
        f.write(f"{timestamp}\t{action}\teml={eml_hash}\tqr={qr_hash}\t{extra}\n")

