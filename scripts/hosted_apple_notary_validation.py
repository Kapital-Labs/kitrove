"""One protected authentication check, with no signing or notary submission."""
import json
import os
import shutil
import shlex
import sys
import tempfile
from pathlib import Path

from hosted_apple_signing import authenticate, native, require
from hosted_apple_process import ProcessCleanupError, cancellation_scope, raise_if_cancelled
from hosted_apple_receipts import valid_source


def validate_credentials():
    source = os.environ.get('GITHUB_SHA', '')
    require(sys.platform == 'darwin' and
        os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted' and
        os.environ.get('GITHUB_REPOSITORY') == 'Kapital-Labs/kitrove' and
        os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and
        os.environ.get('GITHUB_REF') == 'refs/heads/main' and
        os.environ.get('GITHUB_RUN_ATTEMPT') == '1' and valid_source(source) and
        source == os.environ.get('KITROVE_DIAGNOSTIC_EXPECTED_SOURCE') and
        source == os.environ.get('KITROVE_NOTARY_VALIDATION_SHA') and
        os.environ.get('KITROVE_SIGNING_REHEARSAL_SHA', '') == '' and
        os.environ.get('KITROVE_HOSTED_SIGNING_READY', '') == '', 'Diagnostic context refused')
    require(not any(os.environ.get(name) for name in ('P12', 'P12_PASSWORD')),
        'Signing credentials are not permitted')
    values = {name: os.environ.pop(name, '') for name in ('APPLE_ID', 'TEAM_ID', 'NOTARY_PASSWORD')}
    require(all(values.values()) and values['TEAM_ID'] == '98RZ36ES7A', 'Credential setup invalid')
    runner = Path(os.environ['RUNNER_TEMP'])
    helper = runner / 'kitrove-notary-keychain'
    require(runner.is_absolute() and helper.is_file() and not helper.is_symlink(),
        'Prebuilt Keychain helper required')
    snapshot = native(['/usr/bin/security', 'list-keychains', '-d', 'user'],
        operation='Keychain search-list snapshot').stdout
    original = shlex.split(snapshot.decode())
    require(original and all(Path(path).is_absolute() for path in original),
        'Invalid original Keychain search list')
    directory = tempfile.mkdtemp(prefix='kitrove-notary-validation-', dir=runner)
    keychain = Path(directory) / 'notary.keychain-db'
    cleanup_safe = True
    with cancellation_scope() as cancellation:
        try:
            native([str(helper)], json.dumps({'path': str(keychain)}).encode(),
                operation='notarization Keychain creation')
            authenticate(['notarytool', 'store-credentials', 'kitrove-validation',
                '--apple-id', values['APPLE_ID'], '--team-id', values['TEAM_ID'],
                '--keychain', str(keychain), '--validate'], values.pop('NOTARY_PASSWORD'))
        except ProcessCleanupError:
            cleanup_safe = False
            raise
        finally:
            if cleanup_safe:
                try:
                    native(['/usr/bin/security', 'list-keychains', '-d', 'user', '-s'] + original,
                        operation='Keychain search-list restoration')
                except ProcessCleanupError:
                    cleanup_safe = False
                    raise
                finally:
                    if cleanup_safe:
                        if keychain.exists():
                            native(['/usr/bin/security', 'delete-keychain', str(keychain)],
                                operation='Keychain cleanup')
                        require(not keychain.exists(), 'Temporary Keychain cleanup failed')
                        shutil.rmtree(directory)
        raise_if_cancelled(cancellation)
    print('Credential validation and cleanup completed; no product signed or submitted.', flush=True)


if __name__ == '__main__':
    try:
        validate_credentials()
    except Exception:
        print('Credential validation failed; provider diagnostics suppressed. No product signed or submitted.')
        raise SystemExit(1)
