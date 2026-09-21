"""Standard-library receipt authentication, also used by Linux regressions."""
import base64
import hashlib
import hmac
import json
import re


def verify_receipt(stdout: str, key: bytes) -> dict | None:
    """Authenticate first; invalid candidate output is an authenticated failure."""
    try:
        envelope = json.loads(stdout)
        body, tag = envelope['body'], envelope['tag']
        if not hmac.compare_digest(hmac.new(key, body.encode(), hashlib.sha256).hexdigest(), tag):
            return None
        receipt = json.loads(body)
        # These fields belong to the supervisor, not to the candidate.
        if (type(receipt['returncode']) is not int
                or type(receipt['timeout']) is not bool
                or type(receipt['overflow']) is not bool
                or receipt['stage'] not in {'compile', 'run'}
                or not re.fullmatch(r'/tmp/ccb-[a-zA-Z0-9_-]+', receipt['cwd'])
                or type(receipt['compile_success']) is not bool
                or any(type(receipt.get(flag, False)) is not bool
                       for flag in ('cleanup_failed', 'supervisor_error'))
                or (receipt['stage'] == 'run' and not receipt['compile_success'])):
            return None
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        return None

    receipt['output_not_decodable'] = False
    try:
        if not isinstance(receipt['outputs'], dict):
            raise ValueError('Invalid output map')
        receipt['outputs'] = {
            name: None if value is None else base64.b64decode(value, validate=True)
            for name, value in receipt['outputs'].items()
        }
        # Keep file bytes for exact comparison. Strict text validation is only
        # a verdict flag, never grounds to reject an authenticated envelope.
        for content in receipt['outputs'].values():
            if content is not None:
                content.decode('utf-8')
        receipt['output'] = base64.b64decode(receipt['output'], validate=True).decode('utf-8')
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        receipt['output_not_decodable'] = True
        receipt['output'] = ''
        receipt['outputs'] = {}
    return receipt


def receipt_failure(receipt: dict) -> str | None:
    """Shared INCORRECT gate; only successful receipts proceed to comparison."""
    if receipt.get('output_not_decodable'):
        return 'output not decodable'
    if receipt.get('cleanup_failed'):
        return 'candidate cleanup failed'
    if receipt.get('supervisor_error'):
        return 'candidate supervision failed'
    if receipt['timeout']:
        return f"{receipt['stage']} timeout"
    if receipt['overflow']:
        return 'output limit exceeded'
    if receipt['returncode'] != 0:
        return f"{receipt['stage']} error (exit {receipt['returncode']})"
    if receipt['stage'] != 'run' or not receipt['compile_success']:
        return 'run did not complete'
    return None
