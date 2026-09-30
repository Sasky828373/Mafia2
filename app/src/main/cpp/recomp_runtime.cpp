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

static bool parity_even8(uint32_t v) {
    v &= 0xFFu;
    v ^= v >> 4; v &= 0xFu;
    return ((0x6996u >> v) & 1u) == 0u;
}
static void set_szp(X86State& cpu, uint32_t r) {
    cpu.set_flag(X86State::ZF, r == 0);
    cpu.set_flag(X86State::SF, (r & 0x80000000u) != 0);
    cpu.set_flag(X86State::PF, parity_even8(r));
}
bool Runtime::read32(uint32_t va, uint32_t& value) const {
    const auto* p = ptr_from_va(va, 4);
    if (!p) return false;
    std::memcpy(&value, p, 4);
    return true;
}
bool Runtime::write32(uint32_t va, uint32_t value) {
    auto* p = ptr_from_va(va, 4);
    if (!p) return false;
    std::memcpy(p, &value, 4);
    return true;
}
uint32_t Runtime::alu_add32(X86State& cpu, uint32_t a, uint32_t b) {
    const uint32_t r = a + b;
    cpu.set_flag(X86State::CF, r < a);
    cpu.set_flag(X86State::OF, ((~(a ^ b) & (a ^ r)) & 0x80000000u) != 0);
    set_szp(cpu, r);
    return r;
}
uint32_t Runtime::alu_sub32(X86State& cpu, uint32_t a, uint32_t b) {
    const uint32_t r = a - b;
    cpu.set_flag(X86State::CF, a < b);
    cpu.set_flag(X86State::OF, (((a ^ b) & (a ^ r)) & 0x80000000u) != 0);
    set_szp(cpu, r);
    return r;
}
void Runtime::alu_test32(X86State& cpu, uint32_t a, uint32_t b) {
    const uint32_t r = a & b;
    cpu.set_flag(X86State::CF, false);
    cpu.set_flag(X86State::OF, false);
    set_szp(cpu, r);
}

uint32_t Runtime::alu_logic32(X86State& cpu, uint32_t value) {
    cpu.set_flag(X86State::CF, false); cpu.set_flag(X86State::OF, false);
    set_szp(cpu, value); return value;
}
uint32_t& Runtime::reg32(X86State& c, uint8_t i) {
    switch(i&7u){case 0:return c.eax;case 1:return c.ecx;case 2:return c.edx;case 3:return c.ebx;case 4:return c.esp;case 5:return c.ebp;case 6:return c.esi;default:return c.edi;}
}
const uint32_t& Runtime::reg32(const X86State& c, uint8_t i) {
    switch(i&7u){case 0:return c.eax;case 1:return c.ecx;case 2:return c.edx;case 3:return c.ebx;case 4:return c.esp;case 5:return c.ebp;case 6:return c.esi;default:return c.edi;}
}
uint32_t Runtime::ea32(const X86State& c,int b,int i,uint8_t scale,int32_t d) {
    uint32_t v=static_cast<uint32_t>(d);
    if(b>=0)v+=reg32(c,static_cast<uint8_t>(b));
    if(i>=0)v+=reg32(c,static_cast<uint8_t>(i))*scale;
    return v;
}

bool Runtime::eval_jcc(const X86State& cpu, uint8_t cc) {
    const bool cf = cpu.flag(X86State::CF);
    const bool pf = cpu.flag(X86State::PF);
    const bool zf = cpu.flag(X86State::ZF);
    const bool sf = cpu.flag(X86State::SF);
    const bool of = cpu.flag(X86State::OF);
    switch (cc & 0x0Fu) {
        case 0x0: return of;                 // JO
        case 0x1: return !of;                // JNO
        case 0x2: return cf;                 // JB/JC
        case 0x3: return !cf;                // JAE/JNC
        case 0x4: return zf;                 // JE/JZ
        case 0x5: return !zf;                // JNE/JNZ
        case 0x6: return cf || zf;           // JBE
        case 0x7: return !cf && !zf;         // JA
        case 0x8: return sf;                 // JS
        case 0x9: return !sf;                // JNS
        case 0xA: return pf;                 // JP/JPE
        case 0xB: return !pf;                // JNP/JPO
        case 0xC: return sf != of;           // JL
        case 0xD: return sf == of;           // JGE
        case 0xE: return zf || (sf != of);   // JLE
        case 0xF: return !zf && (sf == of);  // JG
    }
    return false;
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
