"""Separate readable uploaded bytes from a verified successful HTTP capture."""


def is_unverified_upload(source):
    return (
        str(source.get('reference', '')).startswith('local:')
        and source.get('origin') == 'operator_supplied'
        and source.get('http_status') == 0
        and source.get('curl_exit') == 0
    )


def readable_content(source):
    return source.get('curl_exit') == 0 and (
        source.get('http_status') == 200 or is_unverified_upload(source)
    )


def is_access_wall(text):
    """Conservative signals; an unrecognized page still needs source review."""
    lower = text.casefold()
    return any(marker in lower for marker in (
        'sign in to continue', 'log in to continue', 'login required',
        'sign in required', 'access denied', 'captcha',
    ))


def source_provenance(source):
    return {
        'origin': source.get('origin'),
        'reference': source.get('reference'),
        'reported_http_status': source.get('http_status'),
        'verified_successful_network_capture': (
            str(source.get('reference', '')).startswith('url:')
            and source.get('origin') == 'whonix_network_capture'
            and source.get('curl_exit') == 0
            and source.get('http_status') == 200
        ),
        'meaning': 'File contents and an operator-supplied URL do not establish a live response, account existence, identity or control.'
        if str(source.get('reference', '')).startswith('local:')
        else 'Interpret preserved response bytes with their capture status and provenance.',
    }
