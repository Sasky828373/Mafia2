#!/usr/bin/env python3
"""Recursive IA-32 control-flow discovery for a user-supplied PE32 image.

Intentionally conservative: it discovers only instruction forms it can size safely.
Unknown opcodes terminate a block and are reported instead of guessed.
"""
import argparse, json, struct
from collections import deque
from pathlib import Path

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def s8(x): return x-256 if x&0x80 else x
def s32(b,o): return struct.unpack_from("<i",b,o)[0]

def parse_pe(b):
    pe=u32(b,0x3c); coff=pe+4; n=u16(b,coff+2); opt=coff+20; osz=u16(b,coff+16)
    base=u32(b,opt+28); entry=u32(b,opt+16); secs=[]
    for i in range(n):
        o=opt+osz+i*40
        name=b[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
        vs,rva,rs,rp=struct.unpack_from("<IIII",b,o+8); ch=u32(b,o+36)
        secs.append((name,rva,vs,rs,rp,ch))
    return base,entry,secs

def rva_to_off(rva,secs):
    for name,va,vs,rs,rp,ch in secs:
        if va <= rva < va+max(vs,rs):
            d=rva-va
            if d < rs: return rp+d
    return None

def exec_rva(rva,secs):
    return any((ch&0x20000000) and va<=rva<va+max(vs,rs) for _,va,vs,rs,_,ch in secs)

def modrm_len(b,o):
    if o>=len(b): return None
    m=b[o]; mod=m>>6; rm=m&7; n=1
    if mod!=3 and rm==4:
        if o+n>=len(b): return None
        sib=b[o+n]; n+=1
        if mod==0 and (sib&7)==5: n+=4
    if mod==0 and rm==5: n+=4
    elif mod==1: n+=1
    elif mod==2: n+=4
    return n

def decode(b,o,rva):
    start=o
    while o<len(b) and b[o] in (0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf0,0xf2,0xf3): o+=1
    if o>=len(b): return None
    op=b[o]; pfx=o-start; o+=1
    if op in (0xc3,0xcb): return pfx+1,"ret",[]
    if op in (0xc2,0xca):
        return (pfx+3,"ret",[]) if o+2<=len(b) else None
    if op in (0xe8,0xe9) and o+4<=len(b):
        ln=pfx+5; t=rva+ln+s32(b,o)
        return ln,("call" if op==0xe8 else "jmp"),[t]
    if op==0xeb and o<len(b):
        ln=pfx+2; return ln,"jmp",[rva+ln+s8(b[o])]
    if 0x70<=op<=0x7f and o<len(b):
        ln=pfx+2; return ln,"jcc",[rva+ln+s8(b[o]),rva+ln]
    if op==0x0f and o<len(b) and 0x80<=b[o]<=0x8f and o+5<=len(b):
        ln=pfx+6; return ln,"jcc",[rva+ln+s32(b,o+1),rva+ln]
    # Safe common one-byte instructions.
    if op in (0x90,0x98,0x99,0x9c,0x9d,0xcc) or 0x40<=op<=0x5f:
        return pfx+1,"linear",[]
    if 0xb8<=op<=0xbf and o+4<=len(b): return pfx+5,"linear",[]
    if op in (0x68,) and o+4<=len(b): return pfx+5,"linear",[]
    if op in (0x6a,) and o<len(b): return pfx+2,"linear",[]
    # ModRM families whose size can be determined without interpreting semantics.
    if op in (0x01,0x03,0x09,0x0b,0x21,0x23,0x29,0x2b,0x31,0x33,0x39,0x3b,0x85,0x87,0x89,0x8b,0x8d,0xff):
        ml=modrm_len(b,o)
        if ml is None: return None
        kind="indirect" if op==0xff else "linear"
        return pfx+1+ml,kind,[]
    return pfx+1,"unknown",[]

def scan(b, max_blocks=250000):
    base,entry,secs=parse_pe(b)
    q=deque([entry]); seen=set(); blocks=[]; unresolved=[]
    while q and len(blocks)<max_blocks:
        start=q.popleft()
        if start in seen or not exec_rva(start,secs): continue
        seen.add(start); rva=start; ins=0; reason="eof"; targets=[]
        while ins<4096:
            off=rva_to_off(rva,secs)
            if off is None: reason="unmapped"; break
            d=decode(b,off,rva)
            if not d: reason="truncated"; break
            ln,kind,t=d; ins+=1; nxt=rva+ln
            if kind=="unknown":
                reason="unknown_opcode"; unresolved.append({"rva":rva,"opcode":b[off]}); break
            if kind=="indirect":
                reason="indirect_control_flow"; unresolved.append({"rva":rva,"opcode":b[off]}); break
            if kind=="call":
                targets+=t; q.extend(x for x in t if exec_rva(x,secs)); rva=nxt; continue
            if kind in ("jmp","jcc"):
                targets+=t; q.extend(x for x in t if exec_rva(x,secs)); reason=kind; break
            if kind=="ret": reason="ret"; break
            rva=nxt
        blocks.append({"rva":start,"va":base+start,"instructions":ins,"end_rva":rva,"reason":reason,"targets_rva":targets})
    return {"image_base":base,"entry_rva":entry,"entry_va":base+entry,"blocks":blocks,
            "block_count":len(blocks),"unresolved":unresolved,
            "unresolved_count":len(unresolved),"queue_remaining":len(q)}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("exe",type=Path); ap.add_argument("-o","--output",type=Path,default=Path("cfg.json")); ap.add_argument("--max-blocks",type=int,default=250000)
    a=ap.parse_args(); b=a.exe.read_bytes(); raw=scan(b,a.max_blocks)
    out=dict(raw)
    out["image_base"]=hex(raw["image_base"]); out["entry_rva"]=hex(raw["entry_rva"]); out["entry_va"]=hex(raw["entry_va"])
    out["blocks"]=[{"start_rva":hex(x["rva"]),"start_va":hex(x["va"]),"instructions":x["instructions"],
                    "end_rva":hex(x["end_rva"]),"reason":x["reason"],
                    "targets_rva":[hex(t) for t in x["targets_rva"]]} for x in raw["blocks"]]
    out["unresolved"]=[{"rva":hex(x["rva"]),"opcode":hex(x["opcode"])} for x in raw["unresolved"]]
    a.output.write_text(json.dumps(out,indent=2)+"\n")
    print(f"blocks={raw['block_count']} unresolved={raw['unresolved_count']} queue={raw['queue_remaining']} -> {a.output}")
if __name__=="__main__": main()
