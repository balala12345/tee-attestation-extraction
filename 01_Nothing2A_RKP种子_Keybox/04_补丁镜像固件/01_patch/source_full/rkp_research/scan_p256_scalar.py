#!/usr/bin/env python3
from pathlib import Path
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
Gx=0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy=0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
O=None
def inv(x): return pow(x, p-2, p)
def add(P,Q):
    if P is None: return Q
    if Q is None: return P
    x1,y1=P; x2,y2=Q
    if x1==x2 and (y1+y2)%p==0: return None
    if P==Q:
        lam=((3*x1*x1+a)*inv(2*y1%p))%p
    else:
        lam=((y2-y1)*inv((x2-x1)%p))%p
    x3=(lam*lam-x1-x2)%p
    y3=(lam*(x1-x3)-y1)%p
    return x3,y3
def mul(k,P=(Gx,Gy)):
    R=None
    while k:
        if k&1: R=add(R,P)
        P=add(P,P); k >>= 1
    return R
def extract_xy(cose):
    # find COSE_Key pairs -2 (0x21) and -3 (0x22): 21 58 20 X, 22 58 20 Y
    i=cose.find(bytes.fromhex('215820'))
    j=cose.find(bytes.fromhex('225820'))
    if i<0 or j<0: raise ValueError('no x/y')
    return cose[i+3:i+35], cose[j+3:j+35]
for mode in ['prod','test']:
    pub=Path(f'rkp_research/rkptee_out_stackdump/rkp_gen_{mode}_pub_len.bin').read_bytes()
    dump=Path(f'rkp_research/rkptee_out_stackdump/rkp_gen_{mode}_priv_len.bin').read_bytes()
    xb,yb=extract_xy(pub); x=int.from_bytes(xb,'big'); y=int.from_bytes(yb,'big')
    print('mode',mode,'target x',xb.hex(),'y',yb.hex())
    found=[]
    for off in range(0,len(dump)-31):
        for endian in ['big','little']:
            k=int.from_bytes(dump[off:off+32], endian)
            if not (1 <= k < n): continue
            # skip common low/structured values
            if k < (1<<128): continue
            R=mul(k)
            if R == (x,y):
                print('FOUND',mode,'off',off,'endian',endian,'scalar',dump[off:off+32].hex())
                found.append((off,endian,dump[off:off+32].hex()))
    print('found_count',len(found))
