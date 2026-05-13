"""
QFAT test script

Runs QFAT on the fixtures folder twice, then checks the output.
Prints PASS or FAIL for each test.

ACPO Good Practice Guide https://private-prosecutions.com/document/acpo-good-practice-guide-for-digital-evidence/
"""

import csv
import hashlib
import json
import shutil
from pathlib import Path
# import cv2
# import numpy as np

import config
import email_parser
import qr_extractor
import virustotal_client
import main

# def decode_with_cv2(image_bytes):
#     """"""

# stub vt so two runs come out the same and save API quota
virustotal_client.submit_url = lambda url: {'malicious': 0, 'suspicious': 0, 'harmless': 1, 'undetected': 91, 'total_engines': 92}
virustotal_client.submit_file = lambda payload: {'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 59, 'total_engines': 59, 'cached': True}

# paths
FIXTURES = Path('tests/fixtures')
RUN1 = Path('tests/run1')
RUN2 = Path('tests/run2')

# expected decoded URLs per fixture
EXPECTED = {
    'variant_a_inline.eml': ['https://www.tudublin.ie'],
    'variant_b_pdf.eml': ['https://www.tudublin.ie'],
    'variant_c_png.eml': ['https://www.tudublin.ie'],
    'variant_d_nested.eml': ['https://www.tudublin.ie', 'https://www.google.com'],
}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def report(name, ok, msg=''):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: {msg}")


def run_qfat(out_dir):
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    config.EVIDENCE_DIR = out_dir / 'evidence'
    config.AUDIT_LOG = out_dir / 'qfat_audit.log'
    csv_path = out_dir / 'forensic_report.csv'
    main.analyse_folder(FIXTURES, csv_path)
    return csv_path


# run QFAT twice, hash fixtures before and after
print('Hashing fixtures before runs...')
hashes_before = {p.name: sha256(p) for p in FIXTURES.glob('*.eml')}

print('\n=== Run 1 ===')
csv1 = run_qfat(RUN1)

print('\nHashing fixtures after run...')
hashes_after = {p.name: sha256(p) for p in FIXTURES.glob('*.eml')}

print('\n=== Run 2 ===')
run_qfat(RUN2)

rows1 = list(csv.DictReader(open(csv1)))
log = (RUN1 / 'qfat_audit.log').read_text()

print('\n=== Test Results ===')

# T1.1: each fixture decodes to the expected URL
fails = []
for fixture, expected_urls in EXPECTED.items():
    matching = [r for r in rows1 if r['eml_filename'] == fixture]
    if not matching:
        fails.append(f'{fixture}: no row')
        continue
    decoded = set()
    for r in matching:
        for u in r['decoded_urls'].split('; '):
            if u:
                decoded.add(u)
    if decoded != set(expected_urls):
        fails.append(f'{fixture}: got {decoded}, expected {set(expected_urls)}')
report('T1.1 decode correctness', not fails, 'all decoded URLs match' if not fails else '; '.join(fails))

# T1.2: no-QR scenario: appends row with qr_present=False
empty = [r for r in rows1 if r['eml_filename'] == 'edge_no_qr.eml']
ok = len(empty) == 1 and empty[0]['qr_present'] == 'False'
report('T1.2 empty case', ok, 'no-QR row OK' if ok else f'got {empty}')

# T2.1: source files unchanged after run (ACPO Principle 1)
fails = [k for k in hashes_before if hashes_before[k] != hashes_after.get(k)]
report('T2.1 source preservation', not fails,
       f'all {len(hashes_before)} hashes match' if not fails else f'altered: {fails}')

# T2.2: two runs produce identical artefacts and manifests
fails = []
for p1 in (RUN1 / 'evidence').rglob('*'):
    if not p1.is_file():
        continue
    rel = p1.relative_to(RUN1 / 'evidence')
    p2 = RUN2 / 'evidence' / rel
    if not p2.exists():
        fails.append(f'missing in run2: {rel}')
        continue
    if p1.name == 'manifest.json':
        m1 = json.loads(p1.read_text())
        m2 = json.loads(p2.read_text())
        m1.pop('processed_utc', None)
        m2.pop('processed_utc', None)
        if m1 != m2:
            fails.append(f'manifest differs: {rel}')
    elif sha256(p1) != sha256(p2):
        fails.append(f'hash differs: {rel}')
report('T2.2 repeatability', not fails, 'two runs identical' if not fails else '; '.join(fails))

# T2.3: re-decode every saved artefact, check URL matches manifest
fails = []
checked = 0
for manifest_path in (RUN1 / 'evidence').glob('*/manifest.json'):
    m = json.loads(manifest_path.read_text())
    for f in m.get('qr_findings', []):
        data = (manifest_path.parent / f['artefact_file']).read_bytes()
        if f['content_type'] == 'application/pdf':
            decoded = qr_extractor.extract_qrs_from_pdf_bytes(data)
        else:
            decoded = qr_extractor.extract_qrs_from_image_bytes(data)
        if f['decoded_url'] not in decoded:
            fails.append(f"{f['artefact_file']}: re-decode mismatch")
        checked += 1
report('T2.3 round-trip', not fails,
       f'{checked} artefacts re-decoded' if not fails else '; '.join(fails))

# T2.4: every CSV row with a qr hash has matching audit log entries
fails = []
checked = 0
for r in rows1:
    h = r.get('qr_image_sha256')
    if not h or h == 'n/a':
        continue
    if f'qr={h}' not in log:
        fails.append(f'{h[:12]}: no audit entry')
        continue
    for action in ('qr_extracted', 'vt_submission_complete'):
        if not any(action in line and f'qr={h}' in line for line in log.splitlines()):
            fails.append(f'{h[:12]}: missing {action}')
    checked += 1
if checked == 0:
    report('T2.4 audit completeness', False, 'no rows had hashes - check CSV has qr_image_sha256 column')
else:
    report('T2.4 audit completeness', not fails,
           f'{checked} rows checked' if not fails else '; '.join(fails))

# T3.1 isn't automated - manual finding from Section 4.2
print('  [SKIP] T3.1 detection gap: see Section 5.1.6 of thesis for manual finding')

# T4.1: corrupt fixture is logged and other files still get processed
ok = ('file=edge_corrupt.eml' in log
      and any(r['eml_filename'] != 'edge_corrupt.eml' for r in rows1))
report('T4.1 malformed input', ok, 'corrupt logged, others processed')