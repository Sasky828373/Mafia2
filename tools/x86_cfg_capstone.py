#!/usr/bin/env python3
"""Capstone-backed IA-32 recursive CFG inventory for user-owned Mafia II PE32."""
import argparse,json,struct
from collections import Counter,deque
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_IMM,X86_OP_MEM

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def pe(b):
    p=u32(b,0x3c); c=p+4; n=u16(b,c+2); os=u16(b,c+16); o=c+20
    base=u32(b,o+28); entry=u32(b,o+16); secs=[]
    for i in range(n):
        s=o+os+i*40; name=b[s:s+8].split(b"\0",1)[0].decode("ascii","replace")
        vs,rv,rs,rp=struct.unpack_from("<IIII",b,s+8); ch=u32(b,s+36)
        secs.append((name,rv,vs,rs,rp,ch))
    return base,entry,secs
def off(rva,secs):
    for _,rv,vs,rs,rp,_ in secs:
        if rv<=rva<rv+max(vs,rs) and rva-rv<rs:return rp+rva-rv
def executable(rva,secs):
    return any((ch&0x20000000) and rv<=rva<rv+max(vs,rs) for _,rv,vs,rs,_,ch in secs)
def jump_table_targets(data,base,secs,ins,max_entries=4096):
    if not ins.operands or ins.operands[0].type!=X86_OP_MEM:return []
    m=ins.operands[0].mem
    # Classic MSVC IA-32 switch: jmp dword ptr [index*4 + absolute_table]
    if m.scale!=4 or not m.index or m.base:return []
    table_va=m.disp & 0xffffffff
    table_rva=(table_va-base)&0xffffffff
    p=off(table_rva,secs)
    if p is None:return []
    out=[]
    for i in range(max_entries):
        q=p+i*4
        if q+4>len(data):break
        va=u32(data,q); rva=(va-base)&0xffffffff
        if not executable(rva,secs):break
        out.append(rva)
    # Avoid treating arbitrary pointer data as a switch table.
    return list(dict.fromkeys(out)) if len(out)>=2 else []

def scan(data,max_blocks=1000000):
    base,entry,secs=pe(data); md=Cs(CS_ARCH_X86,CS_MODE_32); md.detail=True
    q=deque([entry]); seen=set(); blocks=[]; mn=Counter(); indirect=[]
    while q and len(blocks)<max_blocks:
        start=q.popleft()
        if start in seen or not executable(start,secs):continue
        seen.add(start); rva=start; count=0; reason="decode"; targets=[]
        while count<4096:
            p=off(rva,secs)
            if p is None: reason="unmapped"; break
            ins=next(md.disasm(data[p:p+15],base+rva,count=1),None)
            if ins is None: reason="decode"; break
            count+=1; mn[ins.mnemonic]+=1; nxt=rva+ins.size
            imm=None
            if ins.operands and ins.operands[0].type==X86_OP_IMM: imm=(ins.operands[0].imm-base)&0xffffffff
            if ins.group(CS_GRP_CALL):
                if imm is not None and executable(imm,secs): targets.append(imm);q.append(imm)
                elif imm is None: indirect.append({"rva":rva,"mnemonic":ins.mnemonic,"op":ins.op_str})
                rva=nxt;continue
            if ins.group(CS_GRP_RET):
                reason="ret";break
            if ins.group(CS_GRP_JUMP):
                conditional=ins.mnemonic not in ("jmp","ljmp")
                if imm is not None and executable(imm,secs):targets.append(imm);q.append(imm)
                else:
                    jt=jump_table_targets(data,base,secs,ins)
                    if jt:
                        targets.extend(jt); q.extend(jt)
                    else:
                        indirect.append({"rva":rva,"mnemonic":ins.mnemonic,"op":ins.op_str})
                if conditional and executable(nxt,secs):targets.append(nxt);q.append(nxt)
                reason="jcc" if conditional else ("jmp" if imm is not None else "indirect_jump");break
            if ins.mnemonic in ("int3","ud2"):
                reason=ins.mnemonic;break
            rva=nxt
        blocks.append({"rva":start,"va":base+start,"instructions":count,"reason":reason,"targets":targets})
    return {"image_base":base,"entry_rva":entry,"entry_va":base+entry,"blocks":blocks,
      "block_count":len(blocks),"queue_remaining":len(q),"indirect":indirect,
      "indirect_count":len(indirect),"resolved_jump_table_edges":sum(len(b["targets"]) for b in blocks if b["reason"]=="indirect_jump"),"mnemonics":mn}
def main():
    a=argparse.ArgumentParser();a.add_argument("exe",type=Path);a.add_argument("-o","--output",type=Path,default=Path("cfg_capstone.json"));a.add_argument("--max-blocks",type=int,default=1000000)
    z=a.parse_args();r=scan(z.exe.read_bytes(),z.max_blocks)
    out={k:v for k,v in r.items() if k!="mnemonics"}
    out["mnemonics"]=[{"name":k,"count":v} for k,v in r["mnemonics"].most_common()]
    z.output.write_text(json.dumps(out,indent=2)+"\n")
    print(f"blocks={r['block_count']} indirect={r['indirect_count']} jt_edges={r['resolved_jump_table_edges']} queue={r['queue_remaining']} unique_mnemonics={len(r['mnemonics'])}")
if __name__=="__main__":main()
