#include "recomp_runtime.h"
#include <sys/mman.h>
#include <array>
#include <cstring>
#include <cstdio>
#include <vector>

namespace m2_generated { bool dispatch(m2::Runtime&, m2::X86State&); }

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
bool Runtime::load_pe32(const char* path) {
    if(!image_ || !path) return false;
    FILE* fp=std::fopen(path,"rb"); if(!fp)return false;
    std::fseek(fp,0,SEEK_END); long n=std::ftell(fp); std::rewind(fp);
    if(n<0x100){std::fclose(fp);return false;}
    std::vector<uint8_t> b(static_cast<size_t>(n));
    if(std::fread(b.data(),1,b.size(),fp)!=b.size()){std::fclose(fp);return false;}
    std::fclose(fp);
    auto r16=[&](size_t o)->uint16_t{uint16_t v{};if(o+2>b.size())return 0;std::memcpy(&v,b.data()+o,2);return v;};
    auto r32=[&](size_t o)->uint32_t{uint32_t v{};if(o+4>b.size())return 0;std::memcpy(&v,b.data()+o,4);return v;};
    if(r16(0)!=0x5A4D)return false;
    const uint32_t pe=r32(0x3c); if(pe+24>b.size() || r32(pe)!=0x00004550)return false;
    const uint16_t sections=r16(pe+6), optsz=r16(pe+20); const size_t opt=pe+24;
    if(r16(opt)!=0x10B || r32(opt+28)!=kImageBase || r32(opt+56)>kImageSize)return false;
    const uint32_t headers=r32(opt+60); if(headers>b.size() || headers>kImageSize)return false;
    std::memset(image_,0,kImageSize); std::memcpy(image_,b.data(),headers);
    const size_t sh=opt+optsz;
    for(uint16_t i=0;i<sections;i++){
        const size_t p=sh+static_cast<size_t>(i)*40; if(p+40>b.size())return false;
        const uint32_t va=r32(p+12), rawsz=r32(p+16), raw=r32(p+20);
        if(rawsz==0)continue;
        if(static_cast<uint64_t>(va)+rawsz>kImageSize || static_cast<uint64_t>(raw)+rawsz>b.size())return false;
        std::memcpy(image_+va,b.data()+raw,rawsz);
    }
    return true;
}
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
bool Runtime::read8(uint32_t va, uint8_t& value) const {
    const auto* p=ptr_from_va(va,1); if(!p)return false; value=*p; return true;
}
bool Runtime::read16(uint32_t va, uint16_t& value) const {
    const auto* p=ptr_from_va(va,2); if(!p)return false; std::memcpy(&value,p,2); return true;
}
bool Runtime::write8(uint32_t va, uint8_t value) {
    auto* p=ptr_from_va(va,1); if(!p)return false; *p=value; return true;
}
bool Runtime::write16(uint32_t va, uint16_t value) {
    auto* p=ptr_from_va(va,2); if(!p)return false; std::memcpy(p,&value,2); return true;
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
static uint32_t width_mask(uint8_t bits){return bits==8?0xffu:(bits==16?0xffffu:0xffffffffu);}
static uint32_t width_sign(uint8_t bits){return bits==8?0x80u:(bits==16?0x8000u:0x80000000u);}
static void set_szp_width(m2::X86State& cpu,uint32_t r,uint8_t bits){
    const uint32_t m=width_mask(bits),s=width_sign(bits);r&=m;
    cpu.set_flag(m2::X86State::ZF,r==0);cpu.set_flag(m2::X86State::SF,(r&s)!=0);
    uint8_t x=static_cast<uint8_t>(r);x^=x>>4;x&=0xf;cpu.set_flag(m2::X86State::PF,((0x9669u>>x)&1u)!=0);
}
uint32_t Runtime::alu_add(X86State& cpu,uint32_t a,uint32_t b,uint8_t bits){
    const uint64_t m=width_mask(bits);a&=m;b&=m;const uint64_t w=static_cast<uint64_t>(a)+b;const uint32_t r=static_cast<uint32_t>(w)&m;
    cpu.set_flag(X86State::CF,w>m);cpu.set_flag(X86State::OF,((~(a^b)&(a^r))&width_sign(bits))!=0);set_szp_width(cpu,r,bits);return r;
}
uint32_t Runtime::alu_sub(X86State& cpu,uint32_t a,uint32_t b,uint8_t bits){
    const uint32_t m=width_mask(bits);a&=m;b&=m;const uint32_t r=(a-b)&m;
    cpu.set_flag(X86State::CF,a<b);cpu.set_flag(X86State::OF,(((a^b)&(a^r))&width_sign(bits))!=0);set_szp_width(cpu,r,bits);return r;
}
uint32_t Runtime::alu_adc(X86State& cpu,uint32_t a,uint32_t b,uint8_t bits){
    const uint32_t c=cpu.flag(X86State::CF)?1u:0u,m=width_mask(bits);a&=m;b&=m;const uint64_t w=static_cast<uint64_t>(a)+b+c;const uint32_t r=static_cast<uint32_t>(w)&m;
    cpu.set_flag(X86State::CF,w>m);cpu.set_flag(X86State::OF,((~(a^b)&(a^r))&width_sign(bits))!=0);set_szp_width(cpu,r,bits);return r;
}
uint32_t Runtime::alu_sbb(X86State& cpu,uint32_t a,uint32_t b,uint8_t bits){
    const uint32_t c=cpu.flag(X86State::CF)?1u:0u,m=width_mask(bits);a&=m;b&=m;const uint64_t sub=static_cast<uint64_t>(b)+c;const uint32_t r=(a-static_cast<uint32_t>(sub))&m;
    cpu.set_flag(X86State::CF,static_cast<uint64_t>(a)<sub);cpu.set_flag(X86State::OF,(((a^b)&(a^r))&width_sign(bits))!=0);set_szp_width(cpu,r,bits);return r;
}
uint32_t Runtime::alu_logic(X86State& cpu,uint32_t v,uint8_t bits){v&=width_mask(bits);cpu.set_flag(X86State::CF,false);cpu.set_flag(X86State::OF,false);set_szp_width(cpu,v,bits);return v;}
uint32_t Runtime::alu_adc32(X86State& cpu,uint32_t a,uint32_t b) {
    const uint32_t c=cpu.flag(X86State::CF)?1u:0u;
    const uint64_t w=static_cast<uint64_t>(a)+b+c; const uint32_t r=static_cast<uint32_t>(w);
    cpu.set_flag(X86State::CF,(w>>32)!=0); cpu.set_flag(X86State::OF,((~(a^b)&(a^r))&0x80000000u)!=0); set_szp(cpu,r); return r;
}
uint32_t Runtime::alu_sbb32(X86State& cpu,uint32_t a,uint32_t b) {
    const uint32_t c=cpu.flag(X86State::CF)?1u:0u; const uint64_t sub=static_cast<uint64_t>(b)+c;
    const uint32_t r=a-static_cast<uint32_t>(sub); cpu.set_flag(X86State::CF,static_cast<uint64_t>(a)<sub);
    cpu.set_flag(X86State::OF,(((a^b)&(a^r))&0x80000000u)!=0); set_szp(cpu,r); return r;
}
uint32_t Runtime::alu_shift32(X86State& cpu,uint32_t v,uint32_t count,uint8_t kind) {
    count&=31u; if(!count)return v; uint32_t r=v;
    if(kind==0){cpu.set_flag(X86State::CF,((v>>(32-count))&1u)!=0);r=v<<count;}
    else if(kind==1){cpu.set_flag(X86State::CF,((v>>(count-1))&1u)!=0);r=v>>count;}
    else {cpu.set_flag(X86State::CF,((v>>(count-1))&1u)!=0);r=static_cast<uint32_t>(static_cast<int32_t>(v)>>count);}
    set_szp(cpu,r); return r;
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
uint16_t Runtime::reg16(const X86State& cpu,uint8_t i){return static_cast<uint16_t>(reg32(cpu,i)&0xffffu);}
uint8_t Runtime::reg8(const X86State& cpu,uint8_t i){
    if(i<4)return static_cast<uint8_t>(reg32(cpu,i)&0xffu);
    return static_cast<uint8_t>((reg32(cpu,i-4)>>8)&0xffu);
}
void Runtime::set_reg16(X86State& cpu,uint8_t i,uint16_t v){auto& r=reg32(cpu,i);r=(r&0xffff0000u)|v;}
void Runtime::set_reg8(X86State& cpu,uint8_t i,uint8_t v){
    if(i<4){auto& r=reg32(cpu,i);r=(r&0xffffff00u)|v;}
    else {auto& r=reg32(cpu,i-4);r=(r&0xffff00ffu)|(static_cast<uint32_t>(v)<<8);}
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
#ifdef M2_HAS_GENERATED_DISPATCH
                if (!m2_generated::dispatch(*this, cpu))
                    return {DispatchResult::MissingBlock, step, cpu.eip};
                break;
#else
                return {DispatchResult::MissingBlock, step, cpu.eip};
#endif
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
