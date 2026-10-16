#!/usr/bin/env python3
from __future__ import annotations
import subprocess
import tempfile
import unittest
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'rkp_research/rkp_tee_probe_csr.c'
LIB = ROOT / 'device_dump/vendor_lib64/libMcClient.so'
NDK_CLANG = Path(os.environ['ANDROID_NDK_CLANG']) if os.environ.get('ANDROID_NDK_CLANG') else None

class RkpCsrClientInitTests(unittest.TestCase):
    def test_compiled_csr_client_includes_keybox_and_ids_init_path(self):
        """Removing the production keybox/attestation_ids init path should fail this test."""
        if NDK_CLANG is None:
            self.skipTest('set ANDROID_NDK_CLANG to run the native compile check')
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / 'rkp_tee_probe_csr'
            subprocess.run([
                str(NDK_CLANG), '-Wall', '-Wextra', '-O2',
                str(SRC), str(LIB), '-o', str(out),
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            strings = subprocess.run(['strings', str(out)], check=True, stdout=subprocess.PIPE, text=True).stdout
        self.assertIn('attest_keybox', strings)
        self.assertIn('attestation_ids', strings)
        self.assertIn('init_keymint_globals', strings)
        self.assertIn('CMD_ATTEST_KEYBOX', strings)
        self.assertIn('CMD_ATTEST_IDS', strings)

if __name__ == '__main__':
    unittest.main()
