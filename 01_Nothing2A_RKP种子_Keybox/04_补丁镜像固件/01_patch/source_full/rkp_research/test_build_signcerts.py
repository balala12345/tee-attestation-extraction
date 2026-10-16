#!/usr/bin/env python3
from __future__ import annotations
import tempfile
import unittest
from pathlib import Path

from rkp_research import build_and_send_signcerts as b

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw'
GEEK = ROOT / 'rkp_research/geek_fetch_20260815_165246'

class BuildSignCertsTests(unittest.TestCase):
    def test_extracts_cose_key_payload_from_maced_public_key(self):
        maced = (RAW / 'rkp_gen_test_pub_len.bin').read_bytes()
        cose = b.extract_cose_key_from_maced_public_key(maced)
        self.assertEqual(len(cose), 0x53)
        self.assertTrue(cose.startswith(bytes.fromhex('a6010203262001215820')))
        self.assertIn(bytes.fromhex('225820'), cose)
        summary = b.cbor_to_summary(cose)
        self.assertEqual(summary['type'], 'map')
        self.assertEqual(summary['len'], 6)

    def test_builds_maced_keys_to_sign_like_rkpd_old_flow(self):
        cose = b.extract_cose_key_from_maced_public_key((RAW / 'rkp_gen_test_pub_len.bin').read_bytes())
        mac = (RAW / 'csr_maced_keys_len.bin').read_bytes()
        out = b.build_maced_keys_to_sign([cose], mac)
        item, end = b.Cbor(out).decode_item(0)
        self.assertEqual(end, len(out))
        self.assertEqual(item.major, 4)
        self.assertEqual(len(item.value), 4)
        self.assertEqual(item.value[0].value, bytes.fromhex('a10105'))
        self.assertEqual(item.value[1].major, 5)
        payload = item.value[2].value
        arr, arr_end = b.Cbor(payload).decode_item(0)
        self.assertEqual(arr_end, len(payload))
        self.assertEqual(arr.major, 4)
        self.assertEqual(len(arr.value), 1)
        self.assertEqual(payload[arr.value[0].start:arr.value[0].end], cose)
        self.assertEqual(item.value[3].value, mac)

    def test_builds_certificate_request_with_raw_cbor_items_and_challenge_bstr(self):
        cose = b.extract_cose_key_from_maced_public_key((RAW / 'rkp_gen_test_pub_len.bin').read_bytes())
        mks = b.build_maced_keys_to_sign([cose], (RAW / 'csr_maced_keys_len.bin').read_bytes())
        req = b.build_certificate_request(
            device_info_raw=(RAW / 'csr_device_info_len.bin').read_bytes(),
            challenge=(GEEK / 'challenge.bin').read_bytes(),
            protected_data_raw=(RAW / 'csr_protected_data_len.bin').read_bytes(),
            maced_keys_to_sign_raw=mks,
            fingerprint='Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys',
        )
        top, end = b.Cbor(req).decode_item(0)
        self.assertEqual(end, len(req))
        self.assertEqual(top.major, 4)
        self.assertEqual(len(top.value), 4)
        self.assertEqual(top.value[0].major, 4)
        self.assertEqual(len(top.value[0].value), 2)
        self.assertEqual(top.value[1].major, 2)
        self.assertEqual(top.value[1].value, (GEEK / 'challenge.bin').read_bytes())
        # ProtectedData is inserted as the raw tagged COSE_Encrypt item returned by TA.
        self.assertEqual(req[top.value[2].start:top.value[2].end], (RAW / 'csr_protected_data_len.bin').read_bytes())
        # MacedKeysToSign is inserted as array, not a bstr.
        self.assertEqual(top.value[3].major, 4)
        self.assertEqual(req[top.value[3].start:top.value[3].end], mks)

    def test_parse_signed_certificates_response_combines_unique_and_shared_der(self):
        shared = bytes.fromhex('308201aa')
        unique1 = bytes.fromhex('308201bb')
        unique2 = bytes.fromhex('308201cc')
        response = b.enc_array_raw([
            b.enc_bstr(shared),
            b.enc_array_raw([b.enc_bstr(unique1), b.enc_bstr(unique2)]),
        ])
        chains = b.parse_signed_certificates_response(response)
        self.assertEqual(chains, [unique1 + shared, unique2 + shared])

    def test_extracts_google_eek_public_keys_from_curve2_chain(self):
        keys = b.extract_eek_public_keys_from_chain((GEEK / 'geek_curve_2.cbor').read_bytes())
        self.assertEqual(
            [k['x'].hex() for k in keys],
            [
                '99b9eedd5ee452f685c64c62dc3e61ab57487d753729ad768032d2b3cb6358d9',
                'be85e746c4a3425a40d9363aa615d02c587e3ddc330232d2fc5e1e87255f7260',
            ],
        )
        self.assertEqual(keys[0]['curve'], 6)
        self.assertEqual(keys[1]['curve'], 4)

    def test_extracts_protected_data_recipient_public_key(self):
        recipients = b.extract_protected_data_recipient_public_keys((RAW / 'csr_protected_data_len.bin').read_bytes())
        self.assertEqual(
            [r['x'].hex() for r in recipients],
            ['567a10a2060dcd3f566083d5af4756664997eff8ea5362a1b29df6336878c01d'],
        )
        self.assertEqual(recipients[0]['curve'], 4)
        self.assertEqual(
            recipients[0]['kid'].hex(),
            'd0aec115ca2acf73ae6bcccbd1961d65e8b1ddd74a1a37b9433a97d599df9808',
        )

    def test_build_summary_reports_protected_data_eek_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            summary = b.build_from_dirs(
                ROOT / 'rkp_research/direct_csr_matrix_20260815_165522/curve2_test1',
                GEEK,
                Path(td),
                'Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys',
            )
        self.assertEqual(
            summary['protected_data_recipient_public_x'],
            ['567a10a2060dcd3f566083d5af4756664997eff8ea5362a1b29df6336878c01d'],
        )
        self.assertEqual(
            summary['google_eek_public_x'],
            [
                '99b9eedd5ee452f685c64c62dc3e61ab57487d753729ad768032d2b3cb6358d9',
                'be85e746c4a3425a40d9363aa615d02c587e3ddc330232d2fc5e1e87255f7260',
            ],
        )
        self.assertEqual(summary['protected_data_recipient_matches_google_eek'], [False])
        self.assertEqual(
            summary['protected_data_recipient_kid'],
            ['d0aec115ca2acf73ae6bcccbd1961d65e8b1ddd74a1a37b9433a97d599df9808'],
        )
        self.assertEqual(
            summary['google_eek_kid'],
            ['d0aec115ca2acf73ae6bcccbd1961d65e8b1ddd74a1a37b9433a97d599df9808'],
        )
        self.assertEqual(summary['protected_data_recipient_kid_matches_google_eek'], [True])

    def test_resolves_stale_space_named_project_paths_to_current_root(self):
        stale = Path('<PROJECT_ROOT>/rkp_research/direct_csr_matrix_20260815_165522')
        self.assertEqual(
            b.resolve_recorded_path(stale),
            ROOT / 'rkp_research/direct_csr_matrix_20260815_165522',
        )

if __name__ == '__main__':
    unittest.main()
