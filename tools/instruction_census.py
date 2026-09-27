#!/usr/bin/env python3
"""Produce a whole-image instruction census using GNU objdump.

Input is a user-owned PE32. Output is metadata only; no game bytes are emitted.
"""
import argparse, collections, json, re, subprocess
from pathlib import Path

INS=re.compile(r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+\s*([a-zA-Z][a-zA-Z0-9.]*)")

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("exe",type=Path); ap.add_argument("-o","--output",type=Path,default=Path("instruction_census.json"))
    a=ap.parse_args()
    p=subprocess.Popen(["objdump","-d","-Mintel",str(a.exe)],stdout=subprocess.PIPE,text=True,errors="replace")
    c=collections.Counter(); total=0
    assert p.stdout
    for line in p.stdout:
        m=INS.match(line)
        if m:
            c[m.group(1).lower()]+=1; total+=1
    rc=p.wait()
    if rc: raise SystemExit(f"objdump failed: {rc}")
    out={"total_decoded_instructions":total,"unique_mnemonics":len(c),
         "mnemonics":[{"name":k,"count":v} for k,v in c.most_common()]}
    a.output.write_text(json.dumps(out,indent=2)+"\n")
    print(f"decoded={total} unique={len(c)} -> {a.output}")
if __name__=="__main__": main()
