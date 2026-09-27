#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from recomp_ir import demo, cpp
s=cpp(demo())
assert "recomp_00401000" in s
assert "cpu.eax = 0x12345678u;" in s
assert "cpu.ebx = cpu.eax;" in s
assert "cpu.ebx = rt.alu_add32(cpu, cpu.ebx, 0x10u);" in s
assert "rt.pop32" in s
print("IR/codegen smoke test PASS")
