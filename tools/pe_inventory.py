#!/usr/bin/env python3
"""Mafia II PE32 whole-image inventory generator.

BYO executable: this repository never contains mafia2.exe or generated game code.
Produces structural metadata used by the ARM64 recompilation pipeline.
"""
import argparse, json, struct, hashlib
from pathlib import Path

def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def cstr(b,o):
    e=b.find(b"\0",o)
    return b[o:e if e>=0 else len(b)].decode("ascii","replace")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("exe", type=Path)
    ap.add_argument("-o","--output",type=Path,default=Path("mafia2_pe_manifest.json"))
    a=ap.parse_args()
    b=a.exe.read_bytes()
    if b[:2]!=b"MZ": raise SystemExit("not an MZ executable")
    pe=u32(b,0x3c)
    if b[pe:pe+4]!=b"PE\0\0": raise SystemExit("invalid PE signature")
    coff=pe+4
    machine=u16(b,coff); nsec=u16(b,coff+2); optsz=u16(b,coff+16)
    opt=coff+20
    if u16(b,opt)!=0x10b: raise SystemExit("expected PE32")
    entry_rva=u32(b,opt+16); image_base=u32(b,opt+28); image_size=u32(b,opt+56)
    sec0=opt+optsz
    sections=[]
    for i in range(nsec):
        o=sec0+i*40
        name=b[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
        vsize,va,rawsize,rawptr=struct.unpack_from("<IIII",b,o+8)
        chars=u32(b,o+36)
        sections.append({"name":name,"va":image_base+va,"rva":va,"virtual_size":vsize,
                         "raw_size":rawsize,"raw_offset":rawptr,
                         "executable":bool(chars & 0x20000000),"characteristics":chars})
    exec_bytes=sum(s["virtual_size"] for s in sections if s["executable"])
    out={"sha256":hashlib.sha256(b).hexdigest(),"size":len(b),"machine":hex(machine),
         "image_base":hex(image_base),"image_size":hex(image_size),
         "entry_rva":hex(entry_rva),"entry_va":hex(image_base+entry_rva),
         "sections":sections,"executable_virtual_bytes":exec_bytes}
    a.output.write_text(json.dumps(out,indent=2)+"\n")
    print(f"wrote {a.output}: {len(sections)} sections, {exec_bytes} executable bytes")

if __name__=="__main__": main()
