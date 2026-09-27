#!/usr/bin/env python3
"""IA-32 ModRM/SIB operand decoder used by the static recompiler."""
from dataclasses import dataclass
REG=("eax","ecx","edx","ebx","esp","ebp","esi","edi")
@dataclass
class EA:
    mod:int; reg:str; rm:str|None; base:str|None; index:str|None; scale:int; disp:int; size:int; register:bool
def sx(v,bits): return v-(1<<bits) if v&(1<<(bits-1)) else v
def decode(data,off=0):
    m=data[off]; mod=m>>6; reg=REG[(m>>3)&7]; rmv=m&7; n=1
    if mod==3: return EA(mod,reg,REG[rmv],None,None,1,0,n,True)
    base=REG[rmv]; index=None; scale=1; disp=0
    if rmv==4:
        sib=data[off+n]; n+=1; scale=1<<(sib>>6); ix=(sib>>3)&7; bv=sib&7
        index=None if ix==4 else REG[ix]
        base=None if mod==0 and bv==5 else REG[bv]
        if mod==0 and bv==5: disp=int.from_bytes(data[off+n:off+n+4],"little"); n+=4
    elif mod==0 and rmv==5:
        base=None; disp=int.from_bytes(data[off+n:off+n+4],"little"); n+=4
    if mod==1: disp=sx(data[off+n],8); n+=1
    elif mod==2: disp=sx(int.from_bytes(data[off+n:off+n+4],"little"),32); n+=4
    return EA(mod,reg,None,base,index,scale,disp,n,False)
