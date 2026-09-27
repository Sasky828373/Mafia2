# Whole-EXE ARM64 recompilation pipeline

This directory contains tooling for processing a user-supplied Mafia II PE32 executable.
No original executable, disassembly, assets, or generated copyrighted game code is committed.

## Stages

1. `pe_inventory.py` validates the complete PE32 image and inventories every section.
2. Decoder stage walks all executable sections and discovers basic blocks from the entry point, direct branches/calls, exception/indirect targets and known tables.
3. IR stage lowers supported IA-32 instructions into a machine-independent representation with explicit x86 flags and 32-bit address semantics.
4. Codegen emits ARM64 C++/LLVM compilation units plus dispatcher metadata.
5. Win32 import thunks bridge platform calls; D3D9 is routed to the graphics translation backend.
6. Validation compares block-level register/memory effects against an x86 reference run.

A full static recompilation is only considered complete when unresolved reachable blocks and unresolved required imports reach zero. Unknown instructions/targets are never silently replaced with no-ops.

## Local inventory

```sh
python3 tools/pe_inventory.py /path/to/mafia2.exe -o build/mafia2_pe_manifest.json
```

Generated outputs under `build/` are intentionally ignored.
