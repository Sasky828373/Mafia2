#!/usr/bin/env python3
"""Capstone IA-32 -> architecture-neutral recomp IR coverage/lifting pass."""
import argparse,json
from collections import Counter
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_GRP_CALL,CS_GRP_JUMP,CS_GRP_RET
from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
import x86_cfg_capstone as cfg

GPR={"eax","ebx","ecx","edx","esi","edi","ebp","esp"}
ALU={"add","sub","and","or","xor","cmp","test","adc","sbb"}
MOV={"mov","movzx","movsx","lea"}
SHIFT={"shl","shr","sar","sal","rol","ror"}

def cls(ins):
    m=ins.mnemonic
    ops=ins.operands
    if ins.group(CS_GRP_RET):return "ret"
    if ins.group(CS_GRP_CALL):return "call_direct" if ops and ops[0].type==X86_OP_IMM else "call_indirect"
    if ins.group(CS_GRP_JUMP):return "jump_direct" if ops and ops[0].type==X86_OP_IMM else "jump_indirect"
    if m in ("push","pop","pushfd","popfd","leave"):return "stack"
    if m in MOV:return "data"
    if m in ALU:return "alu"
    if m in SHIFT:return "shift"
    if m in ("inc","dec","neg","not","imul","mul","idiv","div"):return "integer"
    if m.startswith(("cmov","set")):return "flags"
    if m.startswith(("rep","movs","stos","lods","scas")):return "string"
    if m.startswith(("f","x87")):return "x87"
    if any(ins.reg_name(r).startswith(("xmm","mm")) for r in ins.regs_read+ins.regs_write):return "simd"
    if m in ("nop","int3","ud2","cld","std","cwde","cdq"):return "misc"
    return "unsupported"

def operand(o,ins):
    if o.type==X86_OP_REG:return {"kind":"reg","reg":ins.reg_name(o.reg),"size":o.size}
    if o.type==X86_OP_IMM:return {"kind":"imm","value":o.imm & 0xffffffff,"size":o.size}
    if o.type==X86_OP_MEM:
        x=o.mem
        return {"kind":"mem","base":ins.reg_name(x.base) if x.base else None,
          "index":ins.reg_name(x.index) if x.index else None,"scale":x.scale,
          "disp":x.disp,"size":o.size}
    return {"kind":"other","size":o.size}

def lift(data,max_blocks):
    c=cfg.scan(data,max_blocks); base,_,secs=cfg.pe(data)
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    cats=Counter();mn=Counter();unsupported=Counter();out=[]
    for b in c["blocks"]:
        r=b["rva"]; ops=[]
        for _ in range(b["instructions"]):
            p=cfg.off(r,secs)
            if p is None:break
            ins=next(md.disasm(data[p:p+15],base+r,count=1),None)
            if not ins:break
            k=cls(ins);cats[k]+=1;mn[ins.mnemonic]+=1
            if k=="unsupported":unsupported[ins.mnemonic]+=1
            ops.append({"va":ins.address,"size":ins.size,"mnemonic":ins.mnemonic,
              "class":k,"operands":[operand(o,ins) for o in ins.operands]})
            r+=ins.size
            if ins.group(CS_GRP_RET) or ins.group(CS_GRP_JUMP):break
        out.append({"va":b["va"],"ops":ops,"targets":b["targets"],"reason":b["reason"]})
    return c,out,cats,mn,unsupported

def main():
    a=argparse.ArgumentParser();a.add_argument("exe",type=Path);a.add_argument("-o","--output",type=Path,default=Path("lift_coverage.json"));a.add_argument("--max-blocks",type=int,default=1000000)
    data=a.exe.read_bytes();c,blocks,cats,mn,bad=lift(data,a.max_blocks)
    report={"entry_va":c["entry_va"],"blocks":len(blocks),"indirect_unresolved":c["indirect_count"],
      "resolved_jump_table_edges":c["resolved_jump_table_edges"],"categories":dict(cats),
      "unsupported_mnemonics":dict(bad),"unique_mnemonics":len(mn)}
    a.output.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps(report,indent=2,sort_keys=True))
if __name__=="__main__":main()
