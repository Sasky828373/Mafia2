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
REG16={"ax":0,"cx":1,"dx":2,"bx":3,"sp":4,"bp":5,"si":6,"di":7}
REG8={"al":0,"cl":1,"dl":2,"bl":3,"ah":4,"ch":5,"dh":6,"bh":7}

def ea(ins,o):
    m=o.mem
    b=REG.get(ins.reg_name(m.base),-1)
    i=REG.get(ins.reg_name(m.index),-1)
    return f"m2::Runtime::ea32(cpu,{b},{i},{m.scale},{m.disp})"

def read_operand(out,ins,o,tmp):
    tmp=f"{tmp}_{ins.address:08X}"
    if o.type==X86_OP_REG:
        rn=ins.reg_name(o.reg)
        if rn in REG: return f"m2::Runtime::reg32(cpu,{REG[rn]})"
        if rn in REG16: return f"static_cast<uint32_t>(m2::Runtime::reg16(cpu,{REG16[rn]}))"
        if rn in REG8: return f"static_cast<uint32_t>(m2::Runtime::reg8(cpu,{REG8[rn]}))"
    if o.type==X86_OP_IMM:
        return f"0x{(o.imm&0xffffffff):08X}u"
    if o.type==X86_OP_MEM and o.size in (1,2,4):
        ctype={1:"uint8_t",2:"uint16_t",4:"uint32_t"}[o.size]
        reader={1:"read8",2:"read16",4:"read32"}[o.size]
        out.append(f"  {ctype} {tmp}{{}}; if(!rt.{reader}({ea(ins,o)},{tmp})) return false;")
        return f"static_cast<uint32_t>({tmp})"
    return None

def write_operand(out,ins,o,value):
    if o.type==X86_OP_REG:
        rn=ins.reg_name(o.reg)
        if rn in REG:
            out.append(f"  m2::Runtime::reg32(cpu,{REG[rn]})={value};"); return True
        if rn in REG16:
            out.append(f"  m2::Runtime::set_reg16(cpu,{REG16[rn]},static_cast<uint16_t>({value}));"); return True
        if rn in REG8:
            out.append(f"  m2::Runtime::set_reg8(cpu,{REG8[rn]},static_cast<uint8_t>({value}));"); return True
    if o.type==X86_OP_MEM and o.size in (1,2,4):
        writer={1:"write8",2:"write16",4:"write32"}[o.size]
        ctype={1:"uint8_t",2:"uint16_t",4:"uint32_t"}[o.size]
        out.append(f"  if(!rt.{writer}({ea(ins,o)},static_cast<{ctype}>({value}))) return false;")
        return True
    return False

def generate(data,max_blocks):
    c=cfg.scan(data,max_blocks);base,_,secs=cfg.pe(data)
    md=Cs(CS_ARCH_X86,CS_MODE_32);md.detail=True
    out=['// generated from user-supplied executable; do not commit game code',
         '#include "recomp_runtime.h"','#include <cstdint>','#include <climits>','namespace m2_generated {']
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
            elif ins.mnemonic in ("inc","dec") and len(ins.operands)==1:
                dst=ins.operands[0]; a=read_operand(out,ins,dst,"a")
                if a is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                bits=dst.size*8
                value=f"m2::Runtime::alu_{ins.mnemonic}(cpu,{a},{bits})"
                if not write_operand(out,ins,dst,value):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
            elif ins.mnemonic in ("movzx","movsx") and len(ins.operands)==2:
                dst,src=ins.operands
                if dst.type!=X86_OP_REG or ins.reg_name(dst.reg) not in REG:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                if src.type==X86_OP_REG:
                    rn=ins.reg_name(src.reg)
                    base=rn[-2:] if rn in ("ax","bx","cx","dx") else rn[-1:] if rn in ("al","bl","cl","dl") else None
                    parent={"ax":"eax","bx":"ebx","cx":"ecx","dx":"edx","al":"eax","bl":"ebx","cl":"ecx","dl":"edx"}.get(rn)
                    raw=f"m2::Runtime::reg32(cpu,{REG[parent]})" if parent else None
                elif src.type==X86_OP_MEM and src.size in (1,2):
                    ctype="uint8_t" if src.size==1 else "uint16_t"
                    reader="read8" if src.size==1 else "read16"
                    narrow=f"narrow_{ins.address:08X}"
                    out.append(f"  {ctype} {narrow}{{}}; if(!rt.{reader}({ea(ins,src)},{narrow})) return false;")
                    raw=f"static_cast<uint32_t>({narrow})"
                else: raw=None
                if raw is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                bits=src.size*8; mask=(1<<bits)-1
                if ins.mnemonic=="movzx": value=f"({raw}&0x{mask:X}u)"
                else: value=f"static_cast<uint32_t>(static_cast<int32_t>(static_cast<int{bits}_t>({raw}&0x{mask:X}u)))"
                write_operand(out,ins,dst,value)
            elif ins.mnemonic=="push" and len(ins.operands)==1:
                value=read_operand(out,ins,ins.operands[0],"v")
                if value is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "push");'];terminated=True;break
                out.append(f"  if(!rt.push32(cpu,{value})) return false;")
            elif ins.mnemonic=="pop" and len(ins.operands)==1:
                popv=f"pop_{ins.address:08X}"
                out.append(f"  uint32_t {popv}{{}}; if(!rt.pop32(cpu,{popv})) return false;")
                if not write_operand(out,ins,ins.operands[0],popv):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "pop");'];terminated=True;break
            elif ins.mnemonic in ("add","sub","adc","sbb","cmp","test","and","or","xor") and len(ins.operands)==2:
                dst,src=ins.operands
                if dst.size not in (1,2,4):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}_width");'];terminated=True;break
                bits=dst.size*8
                a=read_operand(out,ins,dst,"a"); b=read_operand(out,ins,src,"b")
                if a is None or b is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                m=ins.mnemonic
                if m=="add": value=f"m2::Runtime::alu_add(cpu,{a},{b},{bits})"
                elif m=="adc": value=f"m2::Runtime::alu_adc(cpu,{a},{b},{bits})"
                elif m=="sbb": value=f"m2::Runtime::alu_sbb(cpu,{a},{b},{bits})"
                elif m in ("sub","cmp"): value=f"m2::Runtime::alu_sub(cpu,{a},{b},{bits})"
                elif m=="test":
                    out.append(f"  m2::Runtime::alu_logic(cpu,({a})&({b}),{bits});"); value=None
                else:
                    op={"and":"&","or":"|","xor":"^"}[m]
                    value=f"m2::Runtime::alu_logic(cpu,({a}) {op} ({b}),{bits})"
                if value is not None and m!="cmp" and not write_operand(out,ins,dst,value):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{m}");'];terminated=True;break
            elif ins.mnemonic in ("shl","sal","shr","sar") and len(ins.operands)==2:
                dst,cnt=ins.operands; a=read_operand(out,ins,dst,"shiftv"); b=read_operand(out,ins,cnt,"shiftc")
                if a is None or b is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                kind=0 if ins.mnemonic in ("shl","sal") else (1 if ins.mnemonic=="shr" else 2)
                value=f"m2::Runtime::alu_shift32(cpu,{a},{b},{kind})"
                if not write_operand(out,ins,dst,value):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
            elif ins.mnemonic.startswith("cmov") and len(ins.operands)==2:
                cc={"cmovo":0,"cmovno":1,"cmovb":2,"cmovae":3,"cmove":4,"cmovne":5,"cmovbe":6,"cmova":7,"cmovs":8,"cmovns":9,"cmovp":10,"cmovnp":11,"cmovl":12,"cmovge":13,"cmovle":14,"cmovg":15}.get(ins.mnemonic)
                dst,src=ins.operands
                value=read_operand(out,ins,src,"cmov")
                if cc is None or value is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                out.append(f"  if(rt.eval_jcc(cpu,{cc})) {{")
                if not write_operand(out,ins,dst,value):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                out.append("  }")
            elif ins.mnemonic.startswith("set") and len(ins.operands)==1:
                cc={"seto":0,"setno":1,"setb":2,"setae":3,"sete":4,"setne":5,"setbe":6,"seta":7,"sets":8,"setns":9,"setp":10,"setnp":11,"setl":12,"setge":13,"setle":14,"setg":15}.get(ins.mnemonic)
                if cc is None or not write_operand(out,ins,ins.operands[0],f"(rt.eval_jcc(cpu,{cc})?1u:0u)"):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
            elif ins.mnemonic in ("cwde","cdq"):
                if ins.mnemonic=="cwde":
                    out.append("  cpu.eax=static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(cpu.eax&0xffffu)));")
                else:
                    out.append("  cpu.edx=(cpu.eax&0x80000000u)?0xffffffffu:0u;")
            elif ins.mnemonic in ("mul","imul") and len(ins.operands)==1:
                src=ins.operands[0]; value=read_operand(out,ins,src,"mulsrc")
                if value is None or src.size not in (1,2,4):
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                bits=src.size*8
                lhs="(cpu.eax&0xffu)" if bits==8 else ("(cpu.eax&0xffffu)" if bits==16 else "cpu.eax")
                if ins.mnemonic=="mul":
                    out.append(f"  {{ const uint64_t wide=static_cast<uint64_t>({lhs})*static_cast<uint64_t>({value});")
                else:
                    ctype={8:"int8_t",16:"int16_t",32:"int32_t"}[bits]
                    out.append(f"  {{ const int64_t wide=static_cast<int64_t>(static_cast<{ctype}>({lhs}))*static_cast<int64_t>(static_cast<{ctype}>({value}));")
                if bits==8:
                    out.append("  cpu.eax=(cpu.eax&0xffff0000u)|static_cast<uint16_t>(wide);")
                    ov="((static_cast<uint64_t>(wide)>>8)&0xffu)!=0u" if ins.mnemonic=="mul" else "(wide<-128 || wide>127)"
                elif bits==16:
                    out.append("  cpu.eax=(cpu.eax&0xffff0000u)|(static_cast<uint32_t>(wide)&0xffffu); cpu.edx=(cpu.edx&0xffff0000u)|((static_cast<uint64_t>(wide)>>16)&0xffffu);")
                    ov="((static_cast<uint64_t>(wide)>>16)&0xffffu)!=0u" if ins.mnemonic=="mul" else "(wide<-32768 || wide>32767)"
                else:
                    out.append("  cpu.eax=static_cast<uint32_t>(wide); cpu.edx=static_cast<uint32_t>(static_cast<uint64_t>(wide)>>32);")
                    ov="(static_cast<uint64_t>(wide)>>32)!=0u" if ins.mnemonic=="mul" else "(wide<static_cast<int64_t>(INT32_MIN) || wide>static_cast<int64_t>(INT32_MAX))"
                out.append(f"  const bool ov={ov}; cpu.set_flag(m2::X86State::CF,ov); cpu.set_flag(m2::X86State::OF,ov); }}")
            elif ins.mnemonic=="imul" and len(ins.operands) in (2,3):
                dst=ins.operands[0]
                if dst.type!=X86_OP_REG or ins.reg_name(dst.reg) not in REG:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "imul");'];terminated=True;break
                if len(ins.operands)==2:
                    a=read_operand(out,ins,dst,"imula"); b=read_operand(out,ins,ins.operands[1],"imulb")
                else:
                    a=read_operand(out,ins,ins.operands[1],"imula"); b=read_operand(out,ins,ins.operands[2],"imulb")
                if a is None or b is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "imul");'];terminated=True;break
                prod=f"static_cast<int64_t>(static_cast<int32_t>({a}))*static_cast<int64_t>(static_cast<int32_t>({b}))"
                value=f"static_cast<uint32_t>({prod})"
                out.append(f"  {{ const int64_t wide={prod}; const uint32_t low=static_cast<uint32_t>(wide); const bool ov=(wide!=static_cast<int64_t>(static_cast<int32_t>(low))); cpu.set_flag(m2::X86State::CF,ov); cpu.set_flag(m2::X86State::OF,ov);")
                write_operand(out,ins,dst,"low")
                out.append("  }")
            elif ins.group(CS_GRP_RET):
                adjust=(ins.operands[0].imm&0xffff) if ins.operands and ins.operands[0].type==X86_OP_IMM else 0
                out += ['  { uint32_t t{}; if (!rt.pop32(cpu,t)) return false; cpu.eip=t;'+(f' cpu.esp+=0x{adjust:X}u;' if adjust else '')+' }','  return true;'];terminated=True;break
            elif ins.group(CS_GRP_JUMP) and ins.operands and ins.operands[0].type==X86_OP_IMM:
                target=ins.operands[0].imm&0xffffffff
                if ins.mnemonic=="jmp": out += [f'  cpu.eip=0x{target:08X}u;','  return true;'];terminated=True;break
                else:
                    cc={"jo":0,"jno":1,"jb":2,"jae":3,"je":4,"jne":5,"jbe":6,"ja":7,"js":8,"jns":9,"jp":10,"jnp":11,"jl":12,"jge":13,"jle":14,"jg":15}.get(ins.mnemonic)
                    if cc is None: out += [f'  return rt.unsupported(0x{ins.address:08X}u, "{ins.mnemonic}");'];terminated=True;break
                    out += [f'  cpu.eip=rt.eval_jcc(cpu,{cc})?0x{target:08X}u:0x{nxt:08X}u;','  return true;'];terminated=True;break
            elif ins.group(CS_GRP_CALL) and ins.operands and ins.operands[0].type!=X86_OP_IMM:
                target=read_operand(out,ins,ins.operands[0],"target")
                if target is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "call_indirect");'];terminated=True;break
                out += [f'  if (!rt.push32(cpu,0x{nxt:08X}u)) return false;',f'  cpu.eip={target};','  return true;'];terminated=True;break
            elif ins.group(CS_GRP_JUMP) and ins.operands and ins.operands[0].type!=X86_OP_IMM:
                target=read_operand(out,ins,ins.operands[0],"target")
                if target is None:
                    out += [f'  return rt.unsupported(0x{ins.address:08X}u, "jmp_indirect");'];terminated=True;break
                out += [f'  cpu.eip={target};','  return true;'];terminated=True;break
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

def write_shards(text,output,blocks_per_shard):
    if blocks_per_shard<=0:
        output.write_text(text); return 1
    # Split only at generated block boundaries; keep namespace/includes valid per TU.
    prefix=text[:text.index("static bool block_")]
    dispatch_at=text.index("bool dispatch(m2::Runtime& rt,m2::X86State& cpu)")
    body=text[text.index("static bool block_"):dispatch_at]
    dispatch=text[dispatch_at:]
    chunks=body.split("static bool block_")[1:]
    output.mkdir(parents=True,exist_ok=True)
    decl=[]; shard_count=0
    for i in range(0,len(chunks),blocks_per_shard):
        group=chunks[i:i+blocks_per_shard]; names=[]
        shard=[prefix]
        for chunk in group:
            name=chunk.split("(",1)[0].strip()
            names.append(name); shard.append("bool "+name+"("+chunk.split("(",1)[1])
        shard.append("}")
        (output/f"mafia2_generated_{shard_count:04d}.cpp").write_text("".join(shard))
        decl.extend(f"bool {n}(m2::Runtime&,m2::X86State&);" for n in names); shard_count+=1
    # Dispatcher TU owns public dispatch and references externally-linked block functions.
    dp=prefix+"\n".join(decl)+"\n"+dispatch
    (output/"mafia2_generated_dispatch.cpp").write_text(dp)
    return shard_count+1

def main():
    ap=argparse.ArgumentParser();ap.add_argument("exe",type=Path);ap.add_argument("-o","--output",type=Path,required=True);ap.add_argument("--max-blocks",type=int,default=1000000);ap.add_argument("--blocks-per-shard",type=int,default=0)
    a=ap.parse_args();generated,c=generate(a.exe.read_bytes(),a.max_blocks);units=write_shards(generated,a.output,a.blocks_per_shard)
    print(f"generated {c['block_count']} reachable block skeletons in {units} C++ unit(s); unresolved indirect={c['indirect_count']}")
if __name__=="__main__":main()
