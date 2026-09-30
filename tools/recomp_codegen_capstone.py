#!/usr/bin/env python3
"""Generate C++ dispatch skeletons from reachable Mafia II IA-32 blocks.

Only semantically implemented classes are emitted as executable operations.
Everything else traps explicitly so generated code can never silently miscompile.
"""
import argparse
from pathlib import Path
from capstone import Cs,CS_ARCH_X86,CS_MODE_32,CS_GRP_RET,CS_GRP_JUMP,CS_GRP_CALL
from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM
import x86_cfg_capstone as cfg

REG={"eax":0,"ecx":1,"edx":2,"ebx":3,"esp":4,"ebp":5,"esi":6,"edi":7}

def ea(ins,o):
    m=o.mem
    b=REG.get(ins.reg_name(m.base),-1)
    i=REG.get(ins.reg_name(m.index),-1)
    return f"m2::Runtime::ea32(cpu,{b},{i},{m.scale},{m.disp})"

def read_operand(out,ins,o,tmp):
    if o.type==X86_OP_REG and ins.reg_name(o.reg) in REG:
        return f"m2::Runtime::reg32(cpu,{REG[ins.reg_name(o.reg)]})"
    if o.type==X86_OP_IMM:
        return f"0x{(o.imm&0xffffffff):08X}u"
    if o.type==X86_OP_MEM and o.size==4:
        out.append(f"  uint32_t {tmp}{{}}; if(!rt.read32({ea(ins,o)},{tmp})) return false;")
        return tmp
    return None

def write_operand(out,ins,o,value):
    if o.type==X86_OP_REG and ins.reg_name(o.reg) in REG:
        out.append(f"  m2::Runtime::reg32(cpu,{REG[ins.reg_name(o.reg)]})={value};")
        return True
    if o.type==X86_OP_MEM and o.size==4:
        out.append(f"  if(!rt.write32({ea(ins,o)},{value})) return false;")
        return True
    return False

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
            elif ins.mnemonic in ("mov","lea") and len(ins.operands)==2:
                dst,src=ins.operands
                if ins.mnemonic=="lea" and src.type==X86_OP_MEM:
                    value=ea(ins,src)
                else:
                    value=read_operand(out,ins,src,"v")
                if value is None or not write_operand(out,ins,dst,value):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
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
