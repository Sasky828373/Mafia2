#include "recomp_runtime.h"
#include <sys/mman.h>
#include <array>
#include <cstring>

namespace m2 {
static uint32_t stub_unimplemented(X86State&) { return 0; }
static constexpr std::array<ImportEntry, 9> kImports{{
    {"KERNEL32.dll", "GetLastError", stub_unimplemented},
    {"USER32.dll", "MessageBoxA", stub_unimplemented},
    {"WINMM.dll", "timeGetTime", stub_unimplemented},
    {"XINPUT1_3.dll", "XInputGetState", stub_unimplemented},
    {"DINPUT8.dll", "DirectInput8Create", stub_unimplemented},
    {"d3d9.dll", "Direct3DCreate9", stub_unimplemented},
    {"d3dx9_42.dll", "D3DXCompileShader", stub_unimplemented},
    {"binkw32.dll", "<Bink API>", stub_unimplemented},
    {"steam_api.dll", "<Steam API>", stub_unimplemented},
}};

Runtime::Runtime() {
    void* p = mmap(nullptr, kImageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) image_ = static_cast<uint8_t*>(p);
}
Runtime::~Runtime() { if (image_) munmap(image_, kImageSize); }
bool Runtime::ready() const { return image_ != nullptr; }
bool Runtime::contains_va(uint32_t va, size_t bytes) const {
    if (va < kImageBase || bytes > kImageSize) return false;
    const uint64_t off = static_cast<uint64_t>(va) - kImageBase;
    return off + bytes <= kImageSize;
}
uint8_t* Runtime::ptr_from_va(uint32_t va, size_t bytes) {
    return (image_ && contains_va(va, bytes)) ? image_ + (va - kImageBase) : nullptr;
}
const uint8_t* Runtime::ptr_from_va(uint32_t va, size_t bytes) const {
    return (image_ && contains_va(va, bytes)) ? image_ + (va - kImageBase) : nullptr;
}
bool Runtime::push32(X86State& cpu, uint32_t value) {
    const uint32_t next = cpu.esp - 4;
    auto* p = ptr_from_va(next, 4);
    if (!p) return false;
    std::memcpy(p, &value, 4); cpu.esp = next; return true;
}
bool Runtime::pop32(X86State& cpu, uint32_t& value) {
    auto* p = ptr_from_va(cpu.esp, 4);
    if (!p) return false;
    std::memcpy(&value, p, 4); cpu.esp += 4; return true;
}

// ARM64-native C++ equivalent of a tiny x86 block used to validate the recomp ABI.
// Semantics: eax=0x12345678; ebx=eax+0x10; ZF=0; ret.
static bool block_00401000(Runtime& rt, X86State& cpu) {
    cpu.eax = 0x12345678u;
    cpu.ebx = cpu.eax + 0x10u;
    cpu.eflags &= ~(1u << 6);
    uint32_t ret{};
    if (!rt.pop32(cpu, ret)) return false;
    cpu.eip = ret;
    return true;
}

DispatchReport Runtime::dispatch(X86State& cpu, uint32_t max_steps) {
    for (uint32_t step = 0; step < max_steps; ++step) {
        if (cpu.eip == kHaltVa) return {DispatchResult::Halted, step, cpu.eip};
        switch (cpu.eip) {
            case kTestBlockVa:
                if (!block_00401000(*this, cpu))
                    return {DispatchResult::MemoryFault, step + 1, cpu.eip};
                break;
            default:
                return {DispatchResult::MissingBlock, step, cpu.eip};
        }
    }
    return {DispatchResult::StepLimit, max_steps, cpu.eip};
}
size_t Runtime::import_count() const { return kImports.size(); }
size_t Runtime::implemented_import_count() const { return 0; }
const ImportEntry* Runtime::find_import(std::string_view dll, std::string_view symbol) const {
    for (const auto& entry : kImports) if (entry.dll == dll && entry.symbol == symbol) return &entry;
    return nullptr;
}
}
