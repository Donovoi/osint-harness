"""Remove the two operator-owned transfer files after collection or import."""
from contextlib import contextmanager


@contextmanager
def temporary_relay(request_path, response_path):
    try:
        yield
    finally:
        failures = []
        for path in (request_path, response_path):
            try:
                path.unlink(missing_ok=True)
            except OSError as error:
                failures.append(type(error).__name__)
        if failures:
            raise RuntimeError('Transfer cleanup incomplete: ' + ', '.join(failures))
