# QFAT Quishing Forensic Analysis Tool

## Prerequisites

- Python 3.12 or later
- A VirusTotal API key: sign up at [virustotal.com](https://www.virustotal.com/)
- zbar, required by pyzbar
  - Windows: included in Python wheel
  - macOS/Linux: install zbar separately: [pyzbar on PyPI](https://pypi.org/project/pyzbar/)

## Setup (Windows)

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
set QFAT_VT_API_KEY=<your-key>
```

## Setup (macOS/Linux)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export QFAT_VT_API_KEY="<your-key>"
```

## Run
1. Place the `.eml` files to analyse in `input_emails/`
2. Run the tool
   ```bash
   python main.py
   ```
3. Output is written to `output/`
   - `forensic_report.csv` contains one row per QR code found (or per email with no QR code)
   - `evidence/<email-name>` holds preserved artefacts and `manifest.json` for each email
   - `qfat_audit.log` maintains audit trail of tool actions

## Tests
- `python test_qfat.py` runs offline tests, requires `.eml` files in `tests/fixtures`
- `python test_integration.py` runs live VirusTotal integration check

## Licence
Licensed under the MIT License