#!/usr/bin/env python3
from __future__ import annotations
import tempfile
import unittest
from pathlib import Path
from rkp_research import signcerts_variants as v
from rkp_research import build_and_send_signcerts as b

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'rkp_research/direct_csr_matrix_20260815_165522/curve2_test1/raw'
GEEK = ROOT / 'rkp_research/geek_fetch_20260815_165246'
FINGERPRINT = 'Nothing/PacmanEEA/Pacman:14/UP1A.231005.007/2401142323:user/release-keys'

class SignCertsVariantTests(unittest.TestCase):
    def test_builds_named_variants_with_distinct_shapes(self):
        variants = v.build_variants(RAW, GEEK, FINGERPRINT)
        names = [x.name for x in variants]
        self.assertEqual(names, [
            'rkpd_old_exact',
            'rkpd_old_empty_unverified',
            'v2_append_unverified',
            'raw_maced_public_payload',
            'challenge_as_array_item',
        ])
        lengths = {x.name: len(x.body) for x in variants}
        self.assertEqual(lengths['rkpd_old_exact'], 877)
        self.assertNotEqual(lengths['rkpd_old_exact'], lengths['v2_append_unverified'])
        self.assertNotEqual(lengths['rkpd_old_exact'], lengths['raw_maced_public_payload'])

    def test_old_exact_variant_matches_existing_builder(self):
        variants = {x.name: x for x in v.build_variants(RAW, GEEK, FINGERPRINT)}
        cose = b.extract_cose_key_from_maced_public_key((RAW / 'rkp_gen_test_pub_len.bin').read_bytes())
        maced = b.build_maced_keys_to_sign([cose], (RAW / 'csr_maced_keys_len.bin').read_bytes())
        expected = b.build_certificate_request(
            (RAW / 'csr_device_info_len.bin').read_bytes(),
            (GEEK / 'challenge.bin').read_bytes(),
            (RAW / 'csr_protected_data_len.bin').read_bytes(),
            maced,
            FINGERPRINT,
        )
        self.assertEqual(variants['rkpd_old_exact'].body, expected)

    def test_writes_variant_manifest_without_sending(self):
        with tempfile.TemporaryDirectory() as td:
            manifest = v.write_variants(RAW, GEEK, Path(td), FINGERPRINT)
            self.assertEqual(len(manifest['variants']), 5)
            for item in manifest['variants']:
                self.assertTrue((Path(td) / item['body_file']).exists())
                self.assertEqual(item['http_status'], None)

if __name__ == '__main__':
    unittest.main()
