#!/usr/bin/env python3
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from modrm import decode
x=decode(bytes.fromhex("44 88 10")) # [eax+ecx*4+0x10]
assert not x.register and x.base=="eax" and x.index=="ecx" and x.scale==4 and x.disp==0x10 and x.size==3
x=decode(bytes.fromhex("C3"))
assert x.register and x.reg=="eax" and x.rm=="ebx"
x=decode(bytes.fromhex("05 78563412"))
assert x.base is None and x.disp==0x12345678
print("ModRM/SIB tests PASS")
