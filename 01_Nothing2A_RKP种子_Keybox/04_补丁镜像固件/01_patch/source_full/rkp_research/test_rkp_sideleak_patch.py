#!/usr/bin/env python3
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / 'device_dump/vendor_app_mcRegistry/0706000000000000000000000000004d.tlbin'
SCRIPT = ROOT / 'rkp_research/patch_0706_rkp_sideleak.py'
SYSTEM_OUT = ROOT / 'patched_ta/0706000000000000000000000000004d.rkp_sideleak.tlbin'
DIRECT_OUT = ROOT / 'patched_ta/0706000000000000000000000000004e.rkp_sideleak.tlbin'
TEXT_BASE = 0x1000
TEXT_OFF = 0xd0
HOOK = 0x21fe0
CAVE = 0x411ac

def off(va):
    return TEXT_OFF + (va - TEXT_BASE)

def enc_b(src, dst, link=False):
    imm = (dst - src) // 4
    if (dst - src) % 4:
        raise ValueError('unaligned branch')
    return struct.pack('<I', (0x94000000 if link else 0x14000000) | (imm & 0x03ffffff))

class RkpSideLeakPatchTest(unittest.TestCase):
    def test_sideleak_patch_preserves_handle_and_adds_tail_copy(self):
        self.assertTrue(SRC.exists(), SRC)
        self.assertTrue(SCRIPT.exists(), 'missing sideleak patch script')
        subprocess.run([sys.executable, str(SCRIPT)], cwd=str(ROOT), check=True)
        self.assertTrue(SYSTEM_OUT.exists(), SYSTEM_OUT)
        self.assertTrue(DIRECT_OUT.exists(), DIRECT_OUT)

        original = SRC.read_bytes()
        patched = SYSTEM_OUT.read_bytes()
        direct = DIRECT_OUT.read_bytes()

        self.assertEqual(patched[0x18:0x28].hex(), '0706000000000000000000000000004d')
        self.assertEqual(direct[0x18:0x28].hex(), '0706000000000000000000000000004e')
        self.assertEqual(patched[off(HOOK):off(HOOK)+4], enc_b(HOOK, CAVE, False))

        cave = patched[off(CAVE):off(CAVE)+0x80]
        # Stub must implement side-channel copy: memcpy(x20 + 0x400, *[sp+216], 196)
        self.assertIn(bytes.fromhex('80021091'), cave, 'missing add x0, x20, #0x400')
        self.assertIn(bytes.fromhex('e16f40f9'), cave, 'missing ldr x1, [sp,#216]')
        self.assertIn(bytes.fromhex('82188052'), cave, 'missing mov w2, #196')
        # It must replay the two original return-path instructions overwritten at 0x21fe0.
        self.assertIn(bytes.fromhex('f96b45a9'), cave, 'missing original ldp x25,x26,[sp,#80]')
        self.assertIn(bytes.fromhex('751301b8'), cave, 'missing original stur w21,[x27,#17]')
        # It must NOT replace TCI private_len/private handle like rkp_ptr196 did.
        self.assertNotIn(bytes.fromhex('609301b8'), cave, 'sideleak stub must not write private_len [x27,#25]')
        self.assertNotIn(bytes.fromhex('e00314aa'), cave[:16], 'sideleak must not memcpy over private_out base')

        # Apart from the hook/cave and direct UUID variant, original file size must stay unchanged.
        self.assertEqual(len(original), len(patched))
        self.assertEqual(len(original), len(direct))

if __name__ == '__main__':
    unittest.main(verbosity=2)
