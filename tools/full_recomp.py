#!/usr/bin/env python3
"""Whole-image recompilation coverage driver.

Runs the conservative CFG scanner over a user-owned PE32, lowers every
reachable block currently supported by x86_to_ir, and writes only generated
output/reports outside the source tree. Generated game code must not be
committed.
"""
import argparse, json, sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import x86_cfg
import x86_to_ir
from recomp_ir import cpp

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("exe", type=Path)
    ap.add_argument("-o","--out", type=Path, required=True)
    ap.add_argument("--max-blocks", type=int, default=1000000)
    ap.add_argument("--max-ins", type=int, default=4096)
    a=ap.parse_args()
    data=a.exe.read_bytes()
    base,entry,secs=x86_to_ir.pe(data)
    a.out.mkdir(parents=True, exist_ok=True)

    # Reuse the CFG scanner's public analysis path when available.
    if not hasattr(x86_cfg, "scan"):
        raise SystemExit("x86_cfg.scan API required by full_recomp.py")
    cfg=x86_cfg.scan(data, max_blocks=a.max_blocks)

    blocks=cfg.get("blocks", [])
    generated=[]
    stops=Counter()
    decoded=0
    for item in blocks:
        rva=item.get("rva")
        if rva is None and "va" in item:
            rva=int(item["va"])-base
        if rva is None:
            continue
        block,end,count,stop=x86_to_ir.lower_linear(data,base,int(rva),secs,a.max_ins)
        decoded += count
        stops[stop] += 1
        generated.append(cpp(block))

    (a.out/"generated_blocks.cpp").write_text(
        "// generated from user-supplied game executable; do not commit\n"+
        "\n".join(generated))
    report={
        "image_base":base,
        "entry_rva":entry,
        "entry_va":base+entry,
        "cfg_blocks":len(blocks),
        "generated_blocks":len(generated),
        "decoded_instructions":decoded,
        "stop_reasons":dict(stops),
        "cfg_unresolved":cfg.get("unresolved",[]),
        "complete": bool(blocks) and not cfg.get("unresolved") and
                    all(k in ("ret","jcc") for k in stops),
    }
    (a.out/"coverage.json").write_text(json.dumps(report,indent=2,sort_keys=True))
    print(json.dumps(report,indent=2,sort_keys=True))
    if not report["complete"]:
        raise SystemExit(2)

if __name__=="__main__":
    main()
