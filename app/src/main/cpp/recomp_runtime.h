#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace m2 {
constexpr uint32_t kImageBase = 0x00400000u;
constexpr uint32_t kImageSize = 0x0195D000u;
constexpr uint32_t kEntryRva  = 0x00A75B0Du;
constexpr uint32_t kEntryVa   = kImageBase + kEntryRva;
constexpr uint32_t kTestBlockVa = 0x00401000u;
constexpr uint32_t kHaltVa = 0xFFFFFFFFu;

struct X86State {
    uint32_t eax{}, ebx{}, ecx{}, edx{};
    uint32_t esi{}, edi{}, ebp{}, esp{};
    uint32_t eip{}, eflags{0x2};

    static constexpr uint32_t CF = 1u << 0;
    static constexpr uint32_t PF = 1u << 2;
    static constexpr uint32_t ZF = 1u << 6;
    static constexpr uint32_t SF = 1u << 7;
    static constexpr uint32_t OF = 1u << 11;

    bool flag(uint32_t mask) const { return (eflags & mask) != 0; }
    void set_flag(uint32_t mask, bool value) {
        eflags = value ? (eflags | mask) : (eflags & ~mask);
    }
};

using ImportThunk = uint32_t(*)(X86State&);
struct ImportEntry {
    std::string_view dll;
    std::string_view symbol;
    ImportThunk thunk;
};

enum class DispatchResult { Halted, MissingBlock, MemoryFault, StepLimit };
struct DispatchReport {
    DispatchResult result{};
    uint32_t steps{};
    uint32_t last_eip{};
};

class Runtime {
public:
    Runtime();
    ~Runtime();
    Runtime(const Runtime&) = delete;
    Runtime& operator=(const Runtime&) = delete;

    bool ready() const;
    uint32_t image_base() const { return kImageBase; }
    uint32_t image_size() const { return kImageSize; }
    uint32_t entry_va() const { return kEntryVa; }
    bool contains_va(uint32_t va, size_t bytes = 1) const;
    uint8_t* ptr_from_va(uint32_t va, size_t bytes = 1);
    const uint8_t* ptr_from_va(uint32_t va, size_t bytes = 1) const;
    bool push32(X86State& cpu, uint32_t value);
    bool pop32(X86State& cpu, uint32_t& value);
    bool read32(uint32_t va, uint32_t& value) const;
    bool write32(uint32_t va, uint32_t value);
    static uint32_t alu_add32(X86State& cpu, uint32_t a, uint32_t b);
    static uint32_t alu_sub32(X86State& cpu, uint32_t a, uint32_t b);
    static void alu_test32(X86State& cpu, uint32_t a, uint32_t b);
    DispatchReport dispatch(X86State& cpu, uint32_t max_steps = 64);
    size_t import_count() const;
    size_t implemented_import_count() const;
    const ImportEntry* find_import(std::string_view dll, std::string_view symbol) const;

private:
    uint8_t* image_{};
};
}
