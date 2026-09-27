#!/usr/bin/env python3
"""Small architecture-neutral IR and C++ emitter for Mafia II static recompilation."""
from dataclasses import dataclass, asdict
import argparse, json
from pathlib import Path

REGS={"eax","ebx","ecx","edx","esi","edi","ebp","esp"}
@dataclass
class Op:
    kind:str
    dst:str|None=None
    a:str|int|None=None
    b:str|int|None=None

@dataclass
class Block:
    va:int
    ops:list[Op]

def validate(block):
    for op in block.ops:
        if op.dst and op.dst not in REGS: raise ValueError(f"bad dst {op.dst}")
        if op.kind not in {"mov_imm","mov","add_imm","sub_imm","cmp","test","jcc","xor","push","pop","set_eip","ret","halt"}:
            raise ValueError(f"unsupported IR op {op.kind}")

def cpp(block):
    validate(block)
    out=[f"static bool recomp_{block.va:08X}(m2::Runtime& rt, m2::X86State& cpu) {{"]
    for x in block.ops:
        if x.kind=="mov_imm": out.append(f"  cpu.{x.dst} = 0x{int(x.a)&0xffffffff:08X}u;")
        elif x.kind=="mov": out.append(f"  cpu.{x.dst} = cpu.{x.a};")
        elif x.kind=="add_imm": out.append(f"  cpu.{x.dst} = rt.alu_add32(cpu, cpu.{x.dst}, 0x{int(x.a)&0xffffffff:X}u);")
        elif x.kind=="sub_imm": out.append(f"  cpu.{x.dst} = rt.alu_sub32(cpu, cpu.{x.dst}, 0x{int(x.a)&0xffffffff:X}u);")
        elif x.kind=="cmp":
            rhs=f"cpu.{x.a}" if isinstance(x.a,str) else f"0x{int(x.a)&0xffffffff:X}u"
            out.append(f"  (void)rt.alu_sub32(cpu, cpu.{x.dst}, {rhs});")
        elif x.kind=="test":
            rhs=f"cpu.{x.a}" if isinstance(x.a,str) else f"0x{int(x.a)&0xffffffff:X}u"
            out.append(f"  rt.alu_test32(cpu, cpu.{x.dst}, {rhs});")
        elif x.kind=="jcc":
            out.append(f"  cpu.eip = rt.eval_jcc(cpu, 0x{int(x.dst)&0xf:X}) ? 0x{int(x.a)&0xffffffff:08X}u : 0x{int(x.b)&0xffffffff:08X}u;")
        elif x.kind=="xor": out.append(f"  cpu.{x.dst} ^= cpu.{x.a};")
        elif x.kind=="push": out.append(f"  if (!rt.push32(cpu, cpu.{x.a})) return false;")
        elif x.kind=="pop": out.append(f"  if (!rt.pop32(cpu, cpu.{x.dst})) return false;")
        elif x.kind=="set_eip": out.append(f"  cpu.eip = 0x{int(x.a)&0xffffffff:08X}u;")
        elif x.kind=="ret":
            out += ["  { uint32_t target{};", "    if (!rt.pop32(cpu, target)) return false;", "    cpu.eip = target; }"]
        elif x.kind=="halt": out.append("  cpu.eip = m2::kHaltVa;")
    out+=["  return true;","}"]
    return "\n".join(out)+"\n"

def demo():
    return Block(0x00401000,[Op("mov_imm","eax",0x12345678),Op("mov","ebx","eax"),Op("add_imm","ebx",0x10),Op("ret")])

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--demo",action="store_true"); ap.add_argument("-o","--output",type=Path)
    a=ap.parse_args()
    if not a.demo: raise SystemExit("currently use --demo; decoder-to-IR wiring is next")
    b=demo(); text=cpp(b)
    if a.output: a.output.write_text(text)
    else: print(text,end="")
if __name__=="__main__": main()
