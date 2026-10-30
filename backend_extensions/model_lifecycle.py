"""Restore only an isolated model container started by this operator session."""

def stop_owned_model(model, owned, ssh):
    if not owned:
        return {'model_stop_required': False, 'owned_model_stopped': False}
    if model not in ('current', 'candidate'):
        raise ValueError('Unsupported isolated model name')
    name = 'osint-model-' + model
    # A failed inspection is unknown, not evidence that the container stopped.
    state = ssh('docker inspect ' + name + ' --format={{.State.Status}}').strip()
    if state in ('running', 'restarting'):
        ssh('docker stop --time 15 ' + name)
        state = ssh('docker inspect ' + name + ' --format={{.State.Status}}').strip()
    if state != 'exited':
        raise RuntimeError('Owned model did not reach a stopped state')
    return {'model_stop_required': True, 'owned_model_stopped': True}

def cleanup_owned_session(cleanup, model, owned, ssh):
    """Attempt both cleanup boundaries even when the first one fails."""
    failures = []
    receipt = {}
    try:
        cleanup()
    except Exception as error:
        failures.append('collection/vault: ' + type(error).__name__)
    try:
        receipt = stop_owned_model(model, owned, ssh)
    except Exception as error:
        failures.append('model: ' + type(error).__name__)
    if failures:
        raise RuntimeError('Session cleanup incomplete; ' + '; '.join(failures))
    return dict(cleanup_complete=True, **receipt)
