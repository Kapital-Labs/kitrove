"""Manual, non-publishing hosted rehearsal; signing remains in the release helpers."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


PRODUCTS = ('kitrove-cli', 'kitrove-installer')
DIST_DIGESTS = {
    'aarch64-apple-darwin': 'aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7',
    'x86_64-apple-darwin': '6243464a8389e006b9256ee548bc795638f1a17113c1b6669c0e05ce89fd05c5',
    'x86_64-pc-windows-msvc': '26e845cabff12a92911ce960af73a86c8f9b2b2d9072b01dfe5b662acf044fa3',
}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def context(env=os.environ):
    target = env.get('DIST_TARGET', '')
    sha = env.get('GITHUB_SHA', '')
    require(target in DIST_DIGESTS and re.fullmatch('[0-9a-f]{40}', sha), 'Invalid rehearsal target or source')
    require(env.get('GITHUB_ACTIONS') == 'true'
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('GITHUB_EVENT_NAME') == 'workflow_dispatch'
            and env.get('GITHUB_REPOSITORY') == 'Kapital-Labs/kitrove'
            and env.get('GITHUB_REF') == 'refs/heads/main'
            and env.get('GITHUB_WORKFLOW_REF') == 'Kapital-Labs/kitrove/.github/workflows/signing-rehearsal.yml@refs/heads/main'
            and env.get('KITROVE_SIGNING_REHEARSAL_SHA') == sha
            and env.get('RELEASE_TAG') == 'v0.0.0', 'Unapproved rehearsal context')
    require((sys.platform == 'win32') == target.endswith('windows-msvc')
            and sys.platform in ('darwin', 'win32'), 'Rehearsal host mismatch')
    return target, sha


def digest(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
            'Handoff must contain only regular, non-redirected files')
    require(info.st_size <= 512 * 1024 * 1024, 'Handoff file exceeds bound')
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def archive_names(target):
    extension = 'zip' if target.endswith('windows-msvc') else 'tar.xz'
    return [f'{product}-{target}.{extension}' for product in PRODUCTS]


def handoff_names(target):
    tools = ['kitrove-release-xtask.exe'] if target.endswith('windows-msvc') else [
        'kitrove-release-xtask', 'kitrove-apple-import']
    archives = archive_names(target)
    return tools + ['dist-manifest.json'] + archives + [name + '.sha256' for name in archives]


def run(*args, **kwargs):
    subprocess.run(args, check=True, **kwargs)


def build(target):
    require(not os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL'), 'Build must not have OIDC access')
    runner = Path(os.environ['RUNNER_TEMP'])
    directory = runner / 'kitrove-rehearsal-dist'
    directory.mkdir()
    windows = target.endswith('windows-msvc')
    extension = 'zip' if windows else 'tar.xz'
    archive = directory / ('dist.' + extension)
    run('curl', '--proto', '=https', '--tlsv1.2', '--fail', '--location', '--silent', '--show-error',
        '--max-time', '180', '--max-filesize', str(128 * 1024 * 1024),
        f'https://github.com/axodotdev/cargo-dist/releases/download/v0.32.0/cargo-dist-{target}.{extension}',
        '--output', str(archive))
    require(digest(archive) == DIST_DIGESTS[target], 'Pinned cargo-dist checksum mismatch')
    # Extraction is only of the reviewed, checksum-pinned tool distribution.
    run('tar', '-xf', str(archive), '-C', str(directory))
    tool = directory / 'dist.exe' if windows else directory / f'cargo-dist-{target}' / 'dist'
    with Path('dist-manifest.json').open('xb') as manifest:
        run(str(tool), 'build', '--tag=v0.0.0', '--artifacts=local', f'--target={target}',
            '--output-format=json', stdout=manifest)
    run('cargo', 'build', '--locked', '-p', 'xtask')
    handoff = Path('signing-input')
    handoff.mkdir()
    suffix = '.exe' if windows else ''
    shutil.copyfile('target/debug/xtask' + suffix, handoff / ('kitrove-release-xtask' + suffix))
    if not windows:
        run('xcrun', 'swiftc', 'scripts/hosted_apple_import.swift', '-o', str(handoff / 'kitrove-apple-import'))
    shutil.copyfile('dist-manifest.json', handoff / 'dist-manifest.json')
    for name in archive_names(target):
        for filename in (name, name + '.sha256'):
            shutil.copyfile(Path('target/distrib') / filename, handoff / filename)


def inventory(target, sha):
    handoff = Path('signing-input')
    require(set(path.name for path in handoff.iterdir()) == set(handoff_names(target)), 'Unexpected build files')
    record = dict(source=sha, target=target, files={name: digest(handoff / name) for name in handoff_names(target)})
    path = handoff / 'inventory.json'
    with path.open('x', encoding='utf-8') as output:
        json.dump(record, output, sort_keys=True)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('inventory=' + digest(path) + '\n')


def verify_handoff(handoff, target, sha, expected):
    require(re.fullmatch('[0-9a-f]{64}', expected), 'Missing build inventory authority')
    require(set(path.name for path in handoff.iterdir()) == set(handoff_names(target) + ['inventory.json']),
            'Unexpected handoff files')
    path = handoff / 'inventory.json'
    require(path.stat().st_size <= 16384 and digest(path) == expected, 'Build inventory digest mismatch')
    record = json.loads(path.read_text(encoding='utf-8'))
    require(set(record) == {'source', 'target', 'files'} and record['source'] == sha
            and record['target'] == target and set(record['files']) == set(handoff_names(target)),
            'Build inventory source, target or file set mismatch')
    for name in handoff_names(target):
        require(digest(handoff / name) == record['files'][name], 'Build handoff digest mismatch')


def provision(target, sha):
    handoff = Path('signing-input')
    verify_handoff(handoff, target, sha, os.environ.get('EXPECTED_INVENTORY', ''))
    runner = Path(os.environ['RUNNER_TEMP'])
    Path('target/distrib').mkdir(parents=True)
    for name in handoff_names(target):
        if name.startswith('kitrove-release-xtask') or name == 'kitrove-apple-import':
            destination = runner / name
        elif name == 'dist-manifest.json':
            destination = Path(name)
        else:
            destination = Path('target/distrib') / name
        require(not destination.exists() and not destination.is_symlink(), 'Handoff destination already exists')
        shutil.copyfile(handoff / name, destination)
        if destination.parent == runner:
            destination.chmod(0o700)


def verify(target, sha):
    windows = target.endswith('windows-msvc')
    tool = Path(os.environ['RUNNER_TEMP']) / ('kitrove-release-xtask.exe' if windows else 'kitrove-release-xtask')
    evidence = Path('signing-evidence')
    evidence.mkdir()
    for name in archive_names(target):
        archive = Path('target/distrib') / name
        run(str(tool), 'verify-application-release-bundle', str(archive), target, 'v0.0.0', 'dist-manifest.json')
        if not windows:
            run(sys.executable, 'scripts/verify_release_archives.py', str(archive))
        for filename in (name, name + '.sha256'):
            shutil.copyfile(archive.parent / filename, evidence / filename)
    shutil.copyfile('dist-manifest.json', evidence / 'dist-manifest.json')
    files = {path.name: digest(path) for path in evidence.iterdir()}
    with (evidence / 'evidence.json').open('x', encoding='utf-8') as output:
        json.dump(dict(source=sha, target=target, run=os.environ['GITHUB_RUN_ID'],
                       attempt=os.environ['GITHUB_RUN_ATTEMPT'], published=False, files=files), output, sort_keys=True)


def main():
    target, sha = context()
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == sha,
            'Checkout differs from approved source')
    runner = Path(os.environ['RUNNER_TEMP'])
    require(runner.is_absolute() and runner.is_dir() and not runner.is_symlink(), 'Invalid runner directory')
    operations = dict(build=lambda: build(target), inventory=lambda: inventory(target, sha),
                      provision=lambda: provision(target, sha), verify=lambda: verify(target, sha))
    require(len(sys.argv) == 2 and sys.argv[1] in operations, 'Unknown rehearsal operation')
    operations[sys.argv[1]]()


if __name__ == '__main__':
    main()
