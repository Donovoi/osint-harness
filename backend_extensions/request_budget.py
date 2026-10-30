"""Deterministic reporting of the trusted collector's unique-URL ledger.

This is accounting, not permission to fetch. Never derive these counts from
uploads, extracted links, model prose or the number of successful captures.
"""
import hashlib
import html
import json
from pathlib import Path


def budget_snapshot(policy, ledger):
    maximum = policy.get('max_urls', 30)
    valid_limit = type(maximum) is int and maximum >= 0
    limit = min(40, maximum) if valid_limit else None
    result = dict(status='unavailable', maximum_unique_urls=limit,
                  used_unique_urls=None, remaining_unique_urls=None,
                  additional_unique_urls_available=False,
                  accounting='Unique URLs in the trusted collection ledger; '
                             'failed HTTP captures count, preflight failures do not. '
                             'This is not a count of HTTP exchanges or tool jobs.',
                  authority='The collection broker alone authorizes requests.')
    if not valid_limit or not isinstance(ledger, dict):
        return result
    # An empty ledger is valid only when supplied by the trusted broker/reader.
    urls = ledger.get('requested_urls', [])
    if (ledger and 'requested_urls' not in ledger or not isinstance(urls, list)
            or any(not isinstance(u, str) or not u for u in urls)):
        return result
    used = len(set(urls))
    result.update(status='over_budget' if used > limit else 'known',
                  used_unique_urls=used, remaining_unique_urls=max(0, limit-used),
                  additional_unique_urls_available=used < limit)
    return result


def read_budget(policy, path):
    """Read only a broker-owned file (mounted read-only into the worker)."""
    try:
        raw = Path(path).read_bytes()
        if len(raw) > 4*1024*1024:
            raise ValueError('ledger too large')
        result = budget_snapshot(policy, json.loads(raw))
        result['ledger_sha256'] = hashlib.sha256(raw).hexdigest()
        return result
    except (OSError, ValueError, TypeError):
        return budget_snapshot(policy, None)


def budget_text(snapshot):
    if snapshot['status'] == 'unavailable':
        count = 'Collection budget unavailable. Do not assume any allowance remains.'
    else:
        count = (f"Unique URL budget: {snapshot['used_unique_urls']} used / "
                 f"{snapshot['maximum_unique_urls']} maximum; "
                 f"{snapshot['remaining_unique_urls']} remaining.")
        if snapshot['remaining_unique_urls'] == 0:
            count += ' No additional unique URLs are available under the current scope.'
        if snapshot['status'] == 'over_budget':
            count += ' Ledger exceeds the policy limit; operator review required.'
    return (count + ' ' + snapshot['accounting'] + ' ' + snapshot['authority'] +
            ' These deterministic counts override any conflicting model statement '
            'about remaining requests. Observing a link does not authorize it.')


def report_views(raw_html, raw_markdown, snapshot):
    """Add current broker accounting without altering historical report bytes."""
    message = budget_text(snapshot)
    title = 'Current collection budget (trusted broker)'
    section = '<section aria-label="Collection budget"><h2>' + title + '</h2><p>' + html.escape(message) + '</p></section>'
    # A standalone body is intentional: the UI sanitizer accepts only inert markup.
    return (section + raw_html,
            '## ' + title + '\n\n' + message + '\n\n' + raw_markdown)
