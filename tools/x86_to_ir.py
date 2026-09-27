#!/usr/bin/env python3
"""Lower safely-decoded IA-32 instructions from a user-supplied PE32 into recomp IR/C++."""
import argparse, struct, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from recomp_ir import Block, Op, cpp

REG=["eax","ecx","edx","ebx","esp","ebp","esi","edi"]
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]

def pe(b):
    p=u32(b,0x3c); c=p+4; n=u16(b,c+2); os=u16(b,c+16); o=c+20
    base=u32(b,o+28); entry=u32(b,o+16); secs=[]
    for i in range(n):
        s=o+os+i*40; vs,rv,rs,rp=struct.unpack_from("<IIII",b,s+8)
        secs.append((rv,vs,rs,rp))
    return base,entry,secs

def off_for(rva,secs):
    for rv,vs,rs,rp in secs:
        if rv<=rva<rv+max(vs,rs) and rva-rv<rs: return rp+rva-rv
    return None

def lower_linear(b,base,start,secs,max_ins=256):
    r=start; ops=[]; decoded=0; stop="limit"
    while decoded<max_ins:
        o=off_for(r,secs)
        if o is None: stop="unmapped"; break
        x=b[o]
        if 0xB8<=x<=0xBF and o+5<=len(b):
            ops.append(Op("mov_imm",REG[x-0xB8],u32(b,o+1))); r+=5
        elif 0x50<=x<=0x57:
            ops.append(Op("push",a=REG[x-0x50])); r+=1
        elif 0x58<=x<=0x5F:
            ops.append(Op("pop",dst=REG[x-0x58])); r+=1
        elif 0x40<=x<=0x47:
            ops.append(Op("add_imm",REG[x-0x40],1)); r+=1
        elif 0x48<=x<=0x4F:
            ops.append(Op("sub_imm",REG[x-0x48],1)); r+=1
        elif x==0xC3:
            ops.append(Op("ret")); r+=1; stop="ret"; decoded+=1; break
        else:
            stop=f"unresolved_opcode_0x{x:02X}"; break
        decoded+=1
    return Block(base+start,ops),r,decoded,stop

def main():
    a=argparse.ArgumentParser(); a.add_argument("exe",type=Path); a.add_argument("--rva",type=lambda x:int(x,0)); a.add_argument("-o","--output",type=Path); a.add_argument("--max-ins",type=int,default=256)
    z=a.parse_args(); b=z.exe.read_bytes(); base,entry,secs=pe(b); start=entry if z.rva is None else z.rva
    block,end,count,stop=lower_linear(b,base,start,secs,z.max_ins)
    text="// generated from user-supplied PE; do not commit generated game code\n"+cpp(block)
    text+=f"// source_rva=0x{start:08X} end_rva=0x{end:08X} decoded={count} stop={stop}\n"
    if z.output: z.output.write_text(text)
    else: print(text,end="")
if __name__=="__main__": main()
