# Mafia II Android ARM64

Experimental clean-room ARM64 host and static-recompilation project for Mafia II Classic.

## Current v0.4 host
- ARM64-only Android APK
- Vulkan 1.1 device detection
- dedicated Mafia II game directory under the app external-files folder
- verifies the user-supplied `mafia2.exe`
- ARM64 recomp runtime and dispatcher self-test
- runtime loader boundary for `libmafia2_recomp.so`
- runtime detection for `libdxvk_d3d9.so` and `libSDL2.so`
- launch ABI: `int mafia2_recomp_main(const char* game_root)`
- no proprietary Mafia II files are distributed

## Architecture
`recompiled Mafia II code -> Win32 compatibility ABI -> D3D9/DXVK -> Vulkan -> Android GPU driver`

The original Windows game files must be supplied by the user. They are never committed to this repository.

## Game folder
The APK creates:

`Android/data/com.m2port.bootstrap/files/Mafia2/`

Copy the user's legally obtained Mafia II Classic installation files there. The host checks for `mafia2.exe` and then hands that directory to the recomp core.

## Recomp core ABI
A future/generated `libmafia2_recomp.so` must export:

`extern "C" int mafia2_recomp_main(const char* game_root);`

The Android host loads it dynamically, so the Java/UI layer does not need to be rebuilt for each translated-code revision.

## Current blocker
The PC executable is PE32/i386. The repository now has the ARM64 runtime/dispatcher and x86 analysis tooling, but a complete generated translation of Mafia II's executable plus Win32/D3D9/PhysX/Bink compatibility is still required before the retail game can boot.

## Build
GitHub Actions builds an ARM64 debug APK using JDK 17, Android SDK/NDK and Gradle.
