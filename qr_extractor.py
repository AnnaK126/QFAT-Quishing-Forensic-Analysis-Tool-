"""
QR code extraction utilities for QFAT

Provides two functions:
    extract_qrs_from_image_bytes(image_bytes) extracts QR codes from raw image bytes (png, jpeg, etc)
    extract_qrs_from_pdf_bytes(pdf_bytes) extracts QR codes from raw PDF bytes

Pillow: https://pillow.readthedocs.io/en/stable/
pyzbar: https://pypi.org/project/pyzbar/
PyMuPDF: https://pymupdf.readthedocs.io/en/latest/

WARNING: User is responsible for treating the strings as URLs ONLY AFTER appropriate validation
"""

from io import BytesIO
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode
import pymupdf

def extract_qrs_from_image_bytes(image_bytes):
    """
    Extract QR codes from raw image bytes (png, jpeg, etc)
    
    Args:
        image_bytes: raw bytes of an image file (png, jpeg, etc)

    Returns:
        List of decoded QR code payloads as UTF-8 strings
        If no QR codes found, returns empty list
        If image cannot be processed, returns empty list
        If QR code cannot be decoded as UTF-8, decodes with replacement characters for invalid bytes
    """

    if not image_bytes:
        return []
    try:
        img = Image.open(BytesIO(image_bytes))
        results = qr_decode(img)
        return [r.data.decode('utf-8', errors='replace') for r in results]
    except Exception:
        return []
    
def extract_qrs_from_pdf_bytes(pdf_bytes):
    """
    Extract QR codes from raw PDF bytes
    
    Args:
        pdf_bytes: raw bytes of a PDF file

    Returns: List of decoded QR code payloads as UTF-8 strings
        If no QR codes are found, returns empty list
        If PDF cannot be processed, returns empty list
        If QR code cannot be decoded as UTF-8, decodes with replacement characters for invalid bytes
    """

    if not pdf_bytes:
        return []
    found = []
    try:
        doc = pymupdf.open(stream=pdf_bytes, filetype='pdf')
        try:
            for page in doc:
                pix = page.get_pixmap(dpi=200)
                page_image_bytes = pix.tobytes('png')
                found.extend(extract_qrs_from_image_bytes(page_image_bytes))
        finally:
            doc.close()
    except Exception:
        return found # return what was found before fail
    return found # return all found