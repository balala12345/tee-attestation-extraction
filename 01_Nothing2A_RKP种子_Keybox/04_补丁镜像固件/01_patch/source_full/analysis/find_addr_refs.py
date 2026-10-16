#!/usr/bin/env python3
import re,sys
obj='analysis/0706_text.llvmobjdump'
inst=[]
pat=re.compile(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+){4}\s+\t([^\s]+)\s*(.*)$')
for line in open(obj):
    m=pat.match(line)
    if not m: continue
    addr=int(m.group(1),16); op=m.group(2); ops=m.group(3).strip()
    inst.append((addr,op,ops,line.rstrip()))

def regnorm(r): return r.strip().split()[0].strip(',')

targets=[int(x,16) for x in sys.argv[1:]] or [0x3ffd7,0x400af,0x40107,0x401f8,0x40218,0x3f970,0x408d0,0x409a8,0x409c0]
for i,(addr,op,ops,line) in enumerate(inst):
    if op!='adrp': continue
    parts=[p.strip() for p in ops.split(',')]
    if len(parts)<2: continue
    reg=parts[0]
    m=re.search(r'0x([0-9a-f]+)', parts[1])
    if not m: continue
    base=int(m.group(1),16)
    # look next 8 for add/ldr using same reg, but tolerate mov
    for j in range(i+1,min(i+10,len(inst))):
        a2,op2,ops2,line2=inst[j]
        parts2=[p.strip() for p in ops2.split(',')]
        if op2=='add' and len(parts2)>=3 and parts2[1]==reg:
            m2=re.search(r'#(0x[0-9a-f]+|\d+)', parts2[2])
            if m2:
                imm=int(m2.group(1).replace('#',''),0)
                val=base+imm
                if val in targets or any(abs(val-t)<=16 for t in targets):
                    print(hex(val), 'at', hex(addr),'->',hex(a2))
                    print(' ',line)
                    print(' ',line2)
                    # print context
                    for k in range(max(0,i-3),min(len(inst),j+6)):
                        print('   ',inst[k][3])
                    print()
        if op2=='ldr' and len(parts2)>=2 and '[' in ops2 and reg in ops2:
            # maybe ldr reg, [xbase,#off]
            m2=re.search(r'\['+re.escape(reg)+r'(?:,\s*#(0x[0-9a-f]+|\d+))?\]', ops2)
            if m2:
                imm=int(m2.group(1) or '0',0)
                val=base+imm
                if val in targets or any(abs(val-t)<=16 for t in targets):
                    print('memref',hex(val),'at',hex(addr),'->',hex(a2))
                    print(' ',line)
                    print(' ',line2)
                    print()
