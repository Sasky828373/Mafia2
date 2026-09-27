#!/usr/bin/env python3
import struct,sys,tempfile,subprocess
from pathlib import Path
# Synthetic PE32 containing: mov eax,12345678; inc eax; push eax; pop ebx; ret
b=bytearray(0x400); b[:2]=b"MZ"; struct.pack_into("<I",b,0x3c,0x80); b[0x80:0x84]=b"PE\0\0"
struct.pack_into("<HHIIIHH",b,0x84,0x14c,1,0,0,0,0xE0,0x102)
o=0x98; struct.pack_into("<H",b,o,0x10b); struct.pack_into("<I",b,o+16,0x1000); struct.pack_into("<I",b,o+28,0x400000); struct.pack_into("<I",b,o+56,0x2000)
s=o+0xE0; b[s:s+5]=b".text"; struct.pack_into("<IIII",b,s+8,0x100,0x1000,0x100,0x200)
struct.pack_into("<I",b,s+36,0x60000020); b[0x200:0x209]=bytes.fromhex("B87856341240505BC3")
with tempfile.TemporaryDirectory() as d:
 p=Path(d)/"x.exe"; p.write_bytes(b)
 r=subprocess.run([sys.executable,"tools/x86_to_ir.py",str(p)],text=True,capture_output=True,check=True)
 assert "recomp_00401000" in r.stdout
 assert "cpu.eax = 0x12345678u;" in r.stdout
 assert "cpu.eax += 0x1u;" in r.stdout
 assert "rt.push32(cpu, cpu.eax)" in r.stdout
 assert "rt.pop32(cpu, cpu.ebx)" in r.stdout
 assert "stop=ret" in r.stdout
print("x86 -> IR -> C++ smoke test PASS")
