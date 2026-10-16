#!/usr/bin/env python3
from pathlib import Path
import subprocess, textwrap
SRC = Path('keymint_tee_client/out_patched/attest_keybox_buf_after.bin')
OUT = Path('extracted_keybox')
OUT.mkdir(exist_ok=True)
b = SRC.read_bytes()

def u32(off): return int.from_bytes(b[off:off+4], 'little')
def der_len(buf, off):
    if buf[off] != 0x30:
        raise ValueError(f'not DER SEQUENCE at {off}: {buf[off:off+8].hex()}')
    first = buf[off+1]
    if first < 0x80:
        return 2 + first
    n = first & 0x7f
    return 2 + n + int.from_bytes(buf[off+2:off+2+n], 'big')

off = 0
version = u32(off); off += 4
manifest = [f'version_or_keybox_number={version}']
for alg in ['ec', 'rsa']:
    plen = u32(off); off += 4
    dl = der_len(b, off)
    if dl != plen:
        raise ValueError(f'{alg} private length mismatch header={plen} der={dl} off={off}')
    priv = b[off:off+plen]
    (OUT / f'{alg}_private_key.der').write_bytes(priv)
    off += plen
    cc = u32(off); off += 4
    manifest.append(f'{alg}_private_key.der len={plen}')
    manifest.append(f'{alg}_cert_count={cc}')
    chain = []
    for i in range(cc):
        clen = u32(off); off += 4
        dl = der_len(b, off)
        if dl != clen:
            raise ValueError(f'{alg} cert {i} length mismatch header={clen} der={dl} off={off}')
        cert = b[off:off+clen]
        (OUT / f'{alg}_cert_{i}.der').write_bytes(cert)
        chain.append(cert)
        manifest.append(f'{alg}_cert_{i}.der len={clen}')
        off += clen
# plaintext part excludes residual encrypted/auth tail left beyond decrypted size
(OUT / 'attestation_keybox_plain.bin').write_bytes(b[:off])
(OUT / 'attestation_keybox_tail_unmodified.bin').write_bytes(b[off:])
manifest.append(f'plaintext_len={off}')
manifest.append(f'tail_unmodified_len={len(b)-off}')
(OUT / 'manifest.txt').write_text('\n'.join(manifest)+'\n')
print('\n'.join(manifest))
