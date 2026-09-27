# Mafia II Android ARM64 Bootstrap

Experimental clean-room Android host for a future Mafia II recompilation port.

## Current scope
- ARM64-only Android target
- Vulkan 1.1 device probe
- loader boundary for a future `libdxvk_d3d9.so`
- loader boundary for a future `libmafia2_recomp.so`
- no proprietary Mafia II game files are included

## Planned architecture
`recompiled Mafia II code -> Win32 compatibility ABI -> D3D9/DXVK -> Vulkan -> Android GPU driver`

The original Windows `mafia2.exe`, PhysX/APEX DLLs, Bink and game assets must be supplied separately by the user and must not be committed to this repository.

## Current blocker
The original PC executable is PE32/i386. Android ARM64 cannot load it natively. The next major milestone is an x86 static recompilation/translation layer plus implementations for the Win32 imports used by translated code.

## Build
GitHub Actions builds an ARM64 debug APK using JDK 17, Android SDK/NDK and Gradle.
