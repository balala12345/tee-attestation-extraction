#!/usr/bin/env python3
from __future__ import annotations
import json
import ssl
import sys
import time
import urllib.request
from pathlib import Path

# Keep the helper relocatable. The output directory is supplied by the caller;
# this root is only a convenience for callers importing the module.
ROOT = Path(__file__).resolve().parents[1]

def enc_uint(n: int) -> bytes:
    if n < 0: raise ValueError('negative uint')
    if n < 24: return bytes([n])
    if n <= 0xff: return bytes([0x18, n])
    if n <= 0xffff: return bytes([0x19]) + n.to_bytes(2, 'big')
    if n <= 0xffffffff: return bytes([0x1a]) + n.to_bytes(4, 'big')
    return bytes([0x1b]) + n.to_bytes(8, 'big')

def enc_type(mt: int, n: int) -> bytes:
    h = mt << 5
    if n < 24: return bytes([h | n])
    if n <= 0xff: return bytes([h | 24, n])
    if n <= 0xffff: return bytes([h | 25]) + n.to_bytes(2, 'big')
    if n <= 0xffffffff: return bytes([h | 26]) + n.to_bytes(4, 'big')
    return bytes([h | 27]) + n.to_bytes(8, 'big')

def enc_text(s: str) -> bytes:
    b = s.encode('utf-8')
    return enc_type(3, len(b)) + b

def enc_map_str_uint_text(items):
    out = enc_type(5, len(items))
    for k, v in items:
        out += enc_text(k)
        if isinstance(v, int): out += enc_uint(v)
        elif isinstance(v, str): out += enc_text(v)
        else: raise TypeError(v)
    return out

class Cbor:
    def __init__(self, data: bytes): self.data=data
    def read_len(self, ai, pos):
        if ai < 24: return ai, pos
        if ai == 24: return self.data[pos], pos+1
        if ai == 25: return int.from_bytes(self.data[pos:pos+2],'big'), pos+2
        if ai == 26: return int.from_bytes(self.data[pos:pos+4],'big'), pos+4
        if ai == 27: return int.from_bytes(self.data[pos:pos+8],'big'), pos+8
        raise ValueError(f'unsupported additional info {ai}')
    def dec(self, pos=0):
        start=pos
        ib=self.data[pos]; pos+=1
        mt=ib>>5; ai=ib&31
        n,pos=self.read_len(ai,pos)
        if mt == 0: return n,start,pos
        if mt == 1: return -1-n,start,pos
        if mt == 2:
            end=pos+n; return self.data[pos:end],start,end
        if mt == 3:
            end=pos+n; return self.data[pos:end].decode('utf-8','replace'),start,end
        if mt == 4:
            arr=[]
            for _ in range(n):
                v,s,e=self.dec(pos); arr.append({'value':v,'start':s,'end':e}); pos=e
            return arr,start,pos
        if mt == 5:
            mp=[]
            for _ in range(n):
                k,ks,ke=self.dec(pos); v,vs,ve=self.dec(ke); mp.append((k,v,ks,ve)); pos=ve
            return mp,start,pos
        if mt == 6:
            v,s,e=self.dec(pos); return {'tag': n, 'value': v},start,e
        if mt == 7:
            if ai == 20: return False,start,pos
            if ai == 21: return True,start,pos
            if ai == 22: return None,start,pos
            return {'simple': ai},start,pos
        raise ValueError(f'bad major type {mt}')

def summarize(v):
    if isinstance(v, bytes): return {'bytes_len': len(v), 'hex_prefix': v[:16].hex()}
    if isinstance(v, list):
        out=[]
        for x in v:
            if isinstance(x, dict) and 'value' in x:
                out.append(summarize(x['value']))
            elif isinstance(x, tuple):
                out.append([summarize(i) for i in x])
            else:
                out.append(summarize(x))
        return out
    if isinstance(v, dict): return {k:summarize(val) for k,val in v.items()}
    if isinstance(v, tuple): return [summarize(i) for i in v]
    return v

def main():
    if len(sys.argv) < 4:
        raise SystemExit(f'usage: {sys.argv[0]} FINGERPRINT SETTINGS_ID OUTDIR [HOST]')
    fp=sys.argv[1]
    sid=int(sys.argv[2],0)
    out=Path(sys.argv[3]).resolve(); out.mkdir(parents=True, exist_ok=True)
    host=sys.argv[4] if len(sys.argv)>4 else 'remoteprovisioning.googleapis.com'
    url=f'https://{host}/v1:fetchEekChain'
    body=enc_map_str_uint_text([('fingerprint', fp), ('id', sid)])
    (out/'request.cbor').write_bytes(body)
    (out/'request_info.json').write_text(json.dumps({'url':url,'fingerprint':fp,'id':sid,'request_len':len(body)},indent=2)+'\n')
    req=urllib.request.Request(url, data=body, method='POST')
    # Java client does not set content type; keep headers minimal.
    with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as resp:
        data=resp.read()
        info={'status': resp.status, 'headers': dict(resp.headers), 'response_len': len(data)}
    (out/'response.cbor').write_bytes(data)
    (out/'response_http.json').write_text(json.dumps(info,indent=2,ensure_ascii=False)+'\n')
    dec=Cbor(data)
    top,s,e=dec.dec(0)
    if e != len(data):
        raise ValueError(f'trailing data at {e}/{len(data)}')
    # response: [ [ [curve, EekCertChain], ... ], challenge, optional config ]
    if not isinstance(top, list) or len(top) not in (2,3):
        raise ValueError('unexpected top-level response array')
    entries=top[0]['value']
    challenge=top[1]['value']
    if not isinstance(challenge, bytes): raise ValueError('challenge not bytes')
    (out/'challenge.bin').write_bytes(challenge)
    curves=[]
    for ent in entries:
        arr=ent['value']
        curve=arr[0]['value']
        chain_start=arr[1]['start']; chain_end=arr[1]['end']
        chain_raw=data[chain_start:chain_end]
        p=out/f'geek_curve_{curve}.cbor'
        p.write_bytes(chain_raw)
        curves.append({'curve':curve,'geek_cbor':str(p),'geek_len':len(chain_raw),'geek_prefix':chain_raw[:16].hex()})
    summary={'http':info,'challenge_len':len(challenge),'challenge_hex':challenge.hex(),'curves':curves,'top_summary':summarize(top)}
    (out/'geek_summary.json').write_text(json.dumps(summary,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(summary,indent=2,ensure_ascii=False))

if __name__=='__main__':
    main()
