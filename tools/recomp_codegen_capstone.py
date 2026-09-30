#!/usr/bin/env python3
"""Generate C++ dispatch skeletons from reachable Mafia II IA-32 blocks.

Only semantically implemented classes are emitted as executable operations.
Everything else traps explicitly so generated code can never silently miscompile.
"""
import argparse
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_GRP_RET,CS_GRP_JUMP,CS_GRP_CALL
from capstone.x86 import X86_OP_IMM
import x86_cfg_capstone as cfg

def generate(data,max_blocks):
    c=cfg.scan(data,max_blocks);base,_,secs=cfg.pe(data)
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    out=['// generated from user-supplied executable; do not commit game code',
         '#include "recomp_runtime.h"','namespace m2_generated {']
    addrs=[]
    for b in c["blocks"]:
        va=b["va"];addrs.append(va)
        out.append(f'static bool block_{va:08X}(m2::Runtime& rt, m2::X86State& cpu) {{')
        r=b["rva"];terminated=False
        for _ in range(b["instructions"]):
            p=cfg.off(r,secs)
            if p is None:break
            ins=next(md.disasm(data[p:p+15],base+r,count=1),None)
            if not ins:break
            nxt=(ins.address+ins.size)&0xffffffff
            if ins.mnemonic=="nop": pass
            elif ins.group(CS_GRP_RET):
                out += ['  { uint32_t t{}; if (!rt.pop32(cpu,t)) return false; cpu.eip=t; }','  return true;'];terminated=True;break
            elif ins.group(CS_GRP_JUMP) and ins.operands and ins.operands[0].type==X86_OP_IMM:
                target=ins.operands[0].imm&0xffffffff
                if ins.mnemonic=="jmp": out += [f'  cpu.eip=0x{target:08X}u;','  return true;'];terminated=True;break
                else:
                    cc={"jo":0,"jno":1,"jb":2,"jae":3,"je":4,"jne":5,"jbe":6,"ja":7,"js":8,"jns":9,"jp":10,"jnp":11,"jl":12,"jge":13,"jle":14,"jg":15}.get(ins.mnemonic)
                    if cc is None: out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                    out += [f'  cpu.eip=rt.eval_jcc(cpu,{cc})?0x{target:08X}u:0x{nxt:08X}u;','  return true;'];terminated=True;break
            elif ins.group(CS_GRP_CALL) and ins.operands and ins.operands[0].type==X86_OP_IMM:
                target=ins.operands[0].imm&0xffffffff
                out += [f'  if (!rt.push32(cpu,0x{nxt:08X}u)) return false;',f'  cpu.eip=0x{target:08X}u;','  return true;'];terminated=True;break
            else:
                # Hard trap until exact semantics for this instruction are emitted.
                safe=ins.mnemonic.replace('"','')
                out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{safe}");'];terminated=True;break
            r+=ins.size
        if not terminated: out += [f'  cpu.eip=0x{(base+r)&0xffffffff:08X}u;','  return true;']
        out.append('}')
    out += ['bool dispatch(m2::Runtime& rt,m2::X86State& cpu) {','  switch(cpu.eip) {']
    for va in addrs: out.append(f'    case 0x{va:08X}u: return block_{va:08X}(rt,cpu);')
    out += ['    default: return false;','  }','}','}']
    return "\n".join(out)+"\n",c

def main():
    ap=argparse.ArgumentParser();ap.add_argument("exe",type=Path);ap.add_argument("-o","--output",type=Path,required=True);ap.add_argument("--max-blocks",type=int,default=1000000)
    a=ap.parse_args();text,c=generate(a.exe.read_bytes(),a.max_blocks);a.output.write_text(text)
    print(f"generated {c['block_count']} reachable block skeletons; unresolved indirect={c['indirect_count']}")
if __name__=="__main__":main()
