"""
QFAT live VirusTotal integration check

Submits one URL and one file to the real VirusTotal API
Confirms responses look sensible.
"""

import email_parser
import virustotal_client
import config
from pathlib import Path

FIXTURES = Path('tests/fixtures')


def report(name, ok, msg=''):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {msg}")


def check_response(stats):
    """Check the VT response has the right keys and integer values."""
    if stats is None:
        return False, 'no response'
    if 'error' in stats:
        return False, f"API error: {stats['error']}"
    for key in ('malicious', 'harmless', 'undetected', 'total_engines'):
        if key not in stats:
            return False, f'missing key: {key}'
        if not isinstance(stats[key], int):
            return False, f'{key} is not an int: {stats[key]!r}'
    return True, (f"{stats['total_engines']} engines, "
                  f"malicious={stats['malicious']}, "
                  f"harmless={stats['harmless']}, "
                  f"undetected={stats['undetected']}")


if not config.VT_API_KEY:
    print('QFAT_VT_API_KEY not set in environment. Aborting.')
    raise SystemExit(1)

# T5.1: live URL submission
print('Submitting test URL to VirusTotal...')
stats = virustotal_client.submit_url('https://www.tudublin.ie/')
ok, msg = check_response(stats)
report('T5.1 live URL submission', ok, msg)

# T5.2: live file submission - use any image attachment from the fixtures
payload = None
content_type = None
source = None
for eml in sorted(FIXTURES.glob('*.eml')):
    try:
        parsed = email_parser.parse_eml(eml)
        for filename, ct, p in parsed['attachments']:
            if ct.startswith('image/'):
                payload, content_type, source = p, ct, eml.name
                break
        if payload:
            break
        for cid, ct, p in parsed['inline_images']:
            if ct.startswith('image/'):
                payload, content_type, source = p, ct, eml.name
                break
        if payload:
            break
    except Exception:
        continue

if payload is None:
    report('T5.2 live file submission', False, 'no image fixture found')
else:
    print(f'Submitting {content_type} from {source} ({len(payload)} bytes)...')
    stats = virustotal_client.submit_file(payload)
    ok, msg = check_response(stats)
    if ok:
        msg += f", cached={stats.get('cached', 'n/a')}"
    report('T5.2 live file submission', ok, msg)