"""Exact-source protected Apple diagnostic; no publication or product execution."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

import hosted_apple_signing as signing
from hosted_apple_process import run_owned, ProcessCancelled, ProcessCleanupError, ProcessTimeout
from hosted_apple_receipts import safe_receipt_lines
import signing_rehearsal as rehearsal
from apple_ticket_control import REQUIREMENT

require = rehearsal.require
TARGETS = ('aarch64-apple-darwin', 'x86_64-apple-darwin')


def context(env=os.environ):
    target, sha = env.get('DIST_TARGET'), env.get('GITHUB_SHA', '')
    require(target in TARGETS and re.fullmatch('[0-9a-f]{40}', sha), 'Invalid diagnostic identity')
    require(sys.platform == 'darwin' and env.get('RUNNER_ARCH') == 'ARM64'
        and env.get('GITHUB_ACTIONS') == 'true' and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
        and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
        and env.get('GITHUB_REPOSITORY') == 'Kapital-Labs/kitrove'
        and env.get('GITHUB_REF') == 'refs/heads/main'
        and env.get('GITHUB_WORKFLOW_REF') == 'Kapital-Labs/kitrove/.github/workflows/apple-ticket-diagnostic.yml@refs/heads/main'
        and env.get('KITROVE_SIGNING_REHEARSAL_SHA') == sha
        and not env.get('KITROVE_HOSTED_SIGNING_READY'), 'Unapproved diagnostic context')
    return target, sha


def version_tag(root):
    data = (root / 'Cargo.toml').read_text()
    require(len(data) <= 128 * 1024, 'Manifest too large')
    matches = re.findall(r'(?m)^\[workspace.package\]\nversion = "([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?)"$', data)
    require(len(matches) == 1, 'Source version missing')
    catalog = json.loads((root / 'release/application-compatibility.json').read_text())
    require(sum(r.get('version') == matches[0] for r in catalog['releases']) == 1,
            'Source version lacks reviewed catalog entry')
    return 'v' + matches[0]


def copy_image(directory, leaf, destination):
    require(leaf in tuple(f'kitrove-installer-{target}.dmg' for target in TARGETS), 'Unexpected image')
    with contextlib.ExitStack() as stack:
        parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        stack.callback(os.close, parent)
        source = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        stack.callback(os.close, source)
        before = os.fstat(source)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                0 < before.st_size <= 512 * 1024 * 1024, 'Invalid diagnostic image')
        output = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(output, 'wb') as target:
            digest = hashlib.sha256()
            total = 0
            while True:
                block = os.read(source, 1024 * 1024)
                if not block:
                    break
                total += len(block)
                require(total <= before.st_size, 'Image grew during copy')
                digest.update(block)
                target.write(block)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(source)
        named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
                                 info.st_ctime_ns, info.st_nlink, info.st_mode)
        require(total == before.st_size and identity(before) == identity(after) == identity(named),
                'Diagnostic image changed')
        require(rehearsal.digest(destination) == digest.hexdigest(), 'Diagnostic copy changed')
        return digest.hexdigest()


def native_status(args):
    result = run_owned(args, timeout=60)
    require(type(result.returncode) is int and -255 <= result.returncode <= 255, 'Invalid native status')
    return result.returncode


def verify_archives(target, tag, runner):
    tool = str(runner / 'kitrove-release-xtask')
    for name in rehearsal.archive_names(target):
        archive = str(Path('target/distrib') / name)
        require(native_status([tool, 'verify-application-release-bundle', archive,
            target, tag, 'dist-manifest.json']) == 0, 'Prepared archive refused')
        require(native_status([sys.executable, 'scripts/verify_release_archives.py', archive]) == 0,
                'Independent archive verifier refused')


def sign(target, sha):
    cleaned = []
    captured = io.StringIO()
    prepared = False
    try:
        with contextlib.redirect_stdout(captured):
            signing.prepare_release(cleanup_observer=lambda: cleaned.append(True))
        prepared = True
    except (ProcessCancelled, ProcessCleanupError):
        print('Diagnostic stopped: cancelled or process cleanup uncertain', flush=True)
        return 1
    except (RuntimeError, OSError, ValueError):
        pass  # Primary failure remains failure; arbitrary exception/provider text is discarded.
    if cleaned != [True]:
        print('Diagnostic refused: credential cleanup not confirmed', flush=True)
        return 1
    output = captured.getvalue().encode()
    require(len(output) <= 256 * 1024, 'Diagnostic output exceeded bound')
    receipts = safe_receipt_lines(output, source_commit=sha, target=target)
    record = dict(schema_version=1, source=sha, target=target, published=False,
                  diagnostic_only=True, preparation_succeeded=prepared, cleanup_confirmed=True,
                  receipts=[json.loads(line.split(' ', 1)[1]) for line in receipts])
    categories = {value for _marker, value in signing.DMG_FAILURE_MARKERS} | {
        'manifest-directory', 'interaction-required', 'certificate-chain', 'security-internal',
        'identity-unavailable', 'keychain-item-unavailable', 'timestamp-service',
        'unclassified-native-failure', 'launch-failure', 'cancelled', 'timeout',
        'process-cleanup-unconfirmed', 'notary-receipt-invalid'}
    failures = re.findall(rb'^Failed: ([a-zA-Z -]+) \[([a-z-]+)\](?: \[[a-z0-9=-]+\])?$', output, re.MULTILINE)
    if len(failures) == 1:
        operation, category = (value.decode('ascii') for value in failures[0])
        if operation in signing.OPERATIONS and category in categories:
            record.update(failed_operation=operation, failure_category=category)
    details = re.findall(rb'^Failed: installer container preparation \[dmg-staple(?:-validation)?\] \[(native-exit=[1-9][0-9]{0,2}|native-termination|native-launch=(?:not-found|permission-denied|other))\]$',
                         output, re.MULTILINE)
    if len(details) == 1:
        detail = details[0].decode('ascii')
        if not detail.startswith('native-exit=') or int(detail.split('=')[1]) <= 255:
            record['failure_detail'] = detail
    runner = Path(os.environ['RUNNER_TEMP']).resolve()
    evidence = Path('diagnostic-evidence')
    evidence.mkdir(mode=0o700)
    status = 0 if prepared else 1
    retained_identity = None
    try:
        leaf = f'kitrove-installer-{target}.dmg'
        image = evidence / leaf
        pending = evidence / (leaf + '.pending')
        record['image_sha256'] = copy_image(runner / 'kitrove-installer-dmg', leaf, pending)
        # Publish the fixed evidence name only after copy identity/hash confirmation.
        # Pending/failed copies are never in the workflow's closed upload list.
        os.link(pending, image, follow_symlinks=False)
        pending.unlink()
        identity = image.lstat()
        retained_identity = (identity.st_dev, identity.st_ino, identity.st_size,
                             identity.st_mtime_ns, identity.st_ctime_ns)
        record['signature_exit'] = native_status(['/usr/bin/codesign', '--verify', '--strict', '-R',
            REQUIREMENT, str(image)])
        record['ticket_exit'] = native_status(['/usr/bin/xcrun', 'stapler', 'validate', '-q', str(image)])
        record['image_unchanged'] = rehearsal.digest(image) == record['image_sha256']
        require(record['image_unchanged'], 'Read-only control changed image')
        if prepared:
            verify_archives(target, os.environ['RELEASE_TAG'], runner)
            require(native_status([str(runner / 'kitrove-release-xtask'), 'verify-installer-dmg',
                str(Path('target/distrib') / f'kitrove-installer-{target}.tar.xz'), target,
                os.environ['RELEASE_TAG'], 'dist-manifest.json', str(runner / 'kitrove-installer-dmg' / leaf)]) == 0,
                'Final container refused')
            require(record['signature_exit'] == record['ticket_exit'] == 0, 'Diagnostic control refused')
    except ProcessCleanupError:
        # Do not upload any evidence after uncertain process ownership.
        print('Diagnostic refused: process cleanup not confirmed', flush=True)
        return 1
    except ProcessCancelled:
        print('Diagnostic stopped: cancelled', flush=True)
        return 1
    except ProcessTimeout:
        record['control_failure'] = 'timeout'
        status = 1
    except (RuntimeError, OSError, ValueError, KeyError):
        record['control_failure'] = 'control-refused'
        status = 1
    try:
        info = image.lstat()
    except FileNotFoundError:
        if 'image_sha256' in record:
            print('Diagnostic refused: retained image missing', flush=True)
            return 1
    except OSError:
        print('Diagnostic refused: retained image unavailable', flush=True)
        return 1
    else:
        if not (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) == retained_identity and
                rehearsal.digest(image) == record.get('image_sha256')):
            print('Diagnostic refused: retained image identity changed', flush=True)
            return 1
    with (evidence / 'diagnostic.json').open('x') as destination:
        json.dump(record, destination, sort_keys=True)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as destination:
            destination.write('evidence_ready=true\n')
    print(json.dumps(record, sort_keys=True), flush=True)
    return status


def main():
    target, sha = context()
    require(rehearsal.subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == sha,
            'Checkout is not approved source')
    os.environ['RELEASE_TAG'] = version_tag(Path.cwd())
    os.environ['KITROVE_PREPARE_DMG'] = '1'
    runner = Path(os.environ['RUNNER_TEMP'])
    require(runner.is_absolute() and runner.is_dir() and not runner.is_symlink()
            and runner.resolve() == runner, 'Invalid runner directory')
    require(len(sys.argv) == 2 and sys.argv[1] in ('build', 'inventory', 'provision', 'sign'),
            'Unknown diagnostic operation')
    operation = sys.argv[1]
    if operation == 'build':
        rehearsal.build(target, tag=os.environ['RELEASE_TAG'], tool_host='aarch64-apple-darwin', notices=True)
    elif operation == 'inventory':
        rehearsal.inventory(target, sha)
    elif operation == 'provision':
        rehearsal.provision(target, sha)
    else:
        return sign(target, sha)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('Apple diagnostic refused; provider details suppressed', flush=True)
        raise SystemExit(1)
