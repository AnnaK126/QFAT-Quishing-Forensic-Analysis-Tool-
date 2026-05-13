"""
VirusTotal API client for URL and file analysis

Functions:
- submit_url(url): submit a URL for analysis, return detection stats or error
- submit_file(file_bytes): submit a file for analysis, return detection stats or error

VT public API v3 docs: https://developers.virustotal.com/reference/overview
"""

import hashlib
import time

import requests

import config

VT_BASE = 'https://www.virustotal.com/api/v3'

def _headers():
    """Return standard auth headers for VT v3"""
    return {'x-apikey': config.VT_API_KEY}

def _summarise_stats(stats):
    """
    Convert VT's analysis stats into standard result dict

    VT returns engine counts under categories: malicious, suspicious, harmless, undetected, timeout
    or sometimes confirmed-timeout or failure

    Given the raw stats dict from VT, return a simplified dict with keys:
    - malicious
    - suspicious
    - harmless
    - undetected
    - total_engines

    If expected keys not present, defaults to 0 for counts to avoid breaking main flow.
    """
    
    malicious = stats.get('malicious', 0)
    suspicious = stats.get('suspicious', 0)
    harmless = stats.get('harmless', 0)
    undetected = stats.get('undetected', 0)
    timeout = stats.get('timeout', 0)
    
    return {
        'malicious': malicious,
        'suspicious': suspicious,
        'harmless': harmless,
        'undetected': undetected,
        'total_engines': malicious + suspicious + harmless + undetected + timeout,
    }

def _poll_analysis(analysis_id, max_attempts):
    """
    Poll VT for analysis results, return stats or error after max attempts

    Args:
        analysis_id: ID string returned by VT on submission
        max_attempts: number of times to poll before giving up

    Returns:
        Success: dict w keys malicious, suspicious, harmless, undetected, total_engines
        Failure: {'error': ...}

    Note: VT rate limits apply to polling, so this function includes a delay between attempts.
    """

    url = f'{VT_BASE}/analyses/{analysis_id}'
    for _ in range(max_attempts):
        time.sleep(config.VT_RATE_LIMIT_SECONDS)
        try:
            response = requests.get(url, headers=_headers(), timeout=30)
        except requests.RequestException as e:
            return {'error': f'network error during poll: {e}'}
        
        if response.status_code != 200:
            return {'error': f'poll failed: HTTP {response.status_code}'}
        
        attributes = response.json().get('data', {}).get('attributes', {})
        if attributes.get('status') == 'completed':
            return _summarise_stats(attributes.get('stats', {}))
        
    return {'error': 'timeout'}

def submit_url(url):
    """
    Submit a URL to VT for analysis, return detection stats or error

    Args:
        url: string URL to analyse

    Returns:
        Success: dict w keys malicious, suspicious, harmless, undetected, total_engines
        Failure: {'error': ...}
    
    Note: VT rate limits apply to submission and polling, so this function includes delays.
    """

    if not url:
        return {'error': 'empty url'}
    
    try:
        submit = requests.post(
            f'{VT_BASE}/urls',
            headers=_headers(),
            data={'url': url},
            timeout=30,
        )
    except requests.RequestException as e:
        return {'error': f'network error during submit: {e}'}
    
    if submit.status_code != 200:
        return {'error': f'submit failed: HTTP {submit.status_code}'}
    
    analysis_id = submit.json().get('data', {}).get('id')
    if not analysis_id:
        return {'error': 'no analysis id returned'}
    
    return _poll_analysis(analysis_id, config.VT_URL_POLL_ATTEMPTS)

def submit_file(file_bytes):
    """
    Submit a file to VT for analysis, return detection stats or error

    First attempts a cached lookup by file hash to avoid unnecessary uploads and run faster.
    If not cached, uploads the file and polls for results.

    Args:
        file_bytes: bytes of the file to analyse

    Returns:
        Success: dict w keys malicious, suspicious, harmless, undetected, total_engines, cached
        Failure: {'error': ...}

    Note: VT rate limits apply to submission and polling, so this function includes delays.
    """

    if not file_bytes:
        return {'error': 'empty file bytes'}
    
    file_hash = hashlib.sha256(file_bytes).hexdigest()

    # Attempt cached lookup by hash
    try:
        cached = requests.get(
            f'{VT_BASE}/files/{file_hash}',
            headers=_headers(),
            timeout=30,
        )
    except requests.RequestException as e:
        return {'error': f'network error during cache check: {e}'}
    
    if cached.status_code == 200:
        attributes = cached.json().get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        if stats:
            result = _summarise_stats(stats)
            result['cached'] = True
            return result
        
    # Not cached, upload and poll
    try:
        upload = requests.post(
            f'{VT_BASE}/files',
            headers=_headers(),
            files={'file': ('upload.bin', file_bytes)},
            timeout=60,
        )
    except requests.RequestException as e:
        return {'error': f'network error during upload: {e}'}
    
    if upload.status_code != 200:
        return {'error': f'upload failed: HTTP {upload.status_code}'}
    
    analysis_id = upload.json().get('data', {}).get('id')
    if not analysis_id:
        return {'error': 'no analysis id returned'}
    
    result = _poll_analysis(analysis_id, config.VT_FILE_POLL_ATTEMPTS)
    if 'error' not in result:
        result['cached'] = False
    return result