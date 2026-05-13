"""
Email parser for QFAT

Parses .eml files to extract metadata, attachments, and inline images.

Metadata includes: filename, message_id, date, from, to, subject

Attachments and inline images are returned as lists of (label, content_type, bytes) tuples.
- For attachments, label is the filename (or 'attached_image' if no filename)
- For inline images, label is 'inline:{content_id}' (or 'inline:unknown' if no content ID)

"""

import email
from email import policy
from pathlib import Path

def parse_eml(filepath):
    """
    Parse an .eml file to extract metadata, attachments, and inline images.

    Args:
        filepath: path to .eml file

    Returns:
        dict with keys:
            'metadata': dict with keys filename, message_id, date, from, to, subject (header fields)
            'attachments': list of (filename, content_type, bytes) tuples
            'inline_images': list of (content_id, content_type, bytes) tuples

    Failure modes:
        - file not found or unreadable: raises exception
        - malformed email: may raise exception or return partial data
    """
    filepath = Path(filepath)

    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    metadata = {
        'filename': filepath.name,
        'message_id': msg.get('Message-ID', ''),
        'date': msg.get('Date', ''),
        'from': msg.get('From', ''),
        'to': msg.get('To', ''),
        'subject': msg.get('Subject', ''),
    }

    attachments = []
    inline_images = []

    for part in msg.walk():
        if part.is_multipart():
            continue    # if multipart email, look at leaves of tree

        content_type = part.get_content_type()
        content_disposition = part.get('Content-Disposition', '')

        if content_type.startswith('image/'):
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            if 'attachment' in content_disposition:
                filename = part.get_filename() or 'attached_image'
                attachments.append((filename, content_type, payload))
            else:
                content_id = part.get('Content-ID', '')
                inline_images.append((content_id, content_type, payload))

        elif content_type == 'application/pdf':
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            filename = part.get_filename() or 'attached.pdf'
            attachments.append((filename, content_type, payload))

    return {
        'metadata': metadata,
        'attachments': attachments,
        'inline_images': inline_images,
    }