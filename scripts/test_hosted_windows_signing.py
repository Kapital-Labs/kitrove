"""No signing or authentication: workflow contracts and native synthetic failures."""
import os
import http.server
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HostedWindowsSigningTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('pwsh'), 'PowerShell transport tests require pwsh')
    def test_bounded_download_transport_without_credentials(self):
        class Interrupted(http.server.BaseHTTPRequestHandler):
            attempts = 0

            def log_message(self, *_args):
                pass

            def do_GET(self):
                type(self).attempts += 1
                self.send_response(200)
                self.send_header('Content-Length', '16' if self.attempts < 3 else '8')
                self.end_headers()
                self.wfile.write(b'partial' if self.attempts < 3 else b'complete')
                self.close_connection = True

        server = http.server.HTTPServer(('127.0.0.1', 0), Interrupted)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as fixture:
                result = subprocess.run([
                    'pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                    str(ROOT / '.github/scripts/test-windows-signing-downloads.ps1'),
                    '-FixtureRoot', fixture,
                    '-LoopbackUri', f'http://127.0.0.1:{server.server_port}/fixed',
                ], check=True, timeout=60, capture_output=True, text=True)
                self.assertEqual(Interrupted.attempts, 3)
                self.assertIn('Pinned download failed: client attempt=1 category=response-ended', result.stdout)
                self.assertNotIn('SECRET', result.stdout + result.stderr)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_workflow_orders_provision_login_sign_cleanup_before_attestation(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        job = workflow.split('  build-local-artifacts:\n', 1)[1].split('  build-global-artifacts:\n', 1)[0]
        positions = [job.index(value) for value in (
            '-Stage Prepare', 'id: windows-login', '-Stage Sign', '-Stage Cleanup',
            '- id: verified-local', 'Attest the exact application archive')]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('environment: release', job)
        self.assertIn("if: always() && runner.os == 'Windows' && steps.windows-login.outcome != 'skipped'", job)
        self.assertIn('client-id: a6f5951e-1036-4a4c-b62e-0e5401820fb2', job)
        self.assertEqual(workflow.count('uses: azure/login@8216e11d8cd9b42fe925c852af8e76311ff067ac'), 1)
        self.assertNotIn('client-secret:', workflow)
        self.assertIn('SIGNING_PROVISIONED: ${{ vars.KITROVE_HOSTED_SIGNING_READY }}', workflow)
        self.assertIn('if [[ "$RUNNER_OS" == "Linux" ]]; then', job)
        self.assertIn('if [[ "$RUNNER_OS" != "Windows" ]]; then\n              python3 scripts/verify_release_archives.py', job)
        self.assertIn('cargo xtask verify-application-release-bundle', job)
        self.assertIn('--stage verified-global-artifacts', workflow)
        self.assertIn('--stage verified-artifacts', workflow)

    def test_both_paths_share_the_same_pinned_provisioner(self):
        common = (ROOT / '.github/scripts/windows-signing-tools.ps1').read_text()
        for name in ('windows-signing-rehearsal.ps1', 'hosted-windows-signing.ps1'):
            script = (ROOT / '.github/scripts' / name).read_text()
            self.assertIn('. "$PSScriptRoot/windows-signing-tools.ps1"', script)
            self.assertIn('Initialize-KitroveSigningTools', script)
            self.assertNotIn('microsoft.trusted.signing.client/', script)
        self.assertIn('1628c77d21ed187c4db998b37b18e267a7f092ae755589e21110c14260b14960', common)
        self.assertIn('3bfcf1e0a3cb42af1692f0a8ed45c15de070c2de86f28a59b2795d904d8a920f', common)
        self.assertLess(common.index('package digest mismatch'), common.index('Expand-Archive'))

    @unittest.skipUnless(os.name == 'nt', 'native Windows PowerShell checks')
    def test_native_guards_cleanup_and_checksum_rejection(self):
        with tempfile.TemporaryDirectory() as fixture:
            subprocess.run([
                'pwsh', '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                str(ROOT / '.github/scripts/test-hosted-windows-signing.ps1'),
                '-FixtureRoot', fixture,
            ], check=True, timeout=60)
