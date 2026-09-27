#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace m2 {
constexpr uint32_t kImageBase = 0x00400000u;
constexpr uint32_t kImageSize = 0x0195D000u;
constexpr uint32_t kEntryRva  = 0x00A75B0Du;
constexpr uint32_t kEntryVa   = kImageBase + kEntryRva;

struct X86State {
    uint32_t eax{}, ebx{}, ecx{}, edx{};
    uint32_t esi{}, edi{}, ebp{}, esp{};
    uint32_t eip{}, eflags{0x2};
};

using ImportThunk = uint32_t(*)(X86State&);

struct ImportEntry {
    std::string_view dll;
    std::string_view symbol;
    ImportThunk thunk;
};

class Runtime {
public:
    Runtime();
    bool ready() const;
    uint32_t image_base() const { return kImageBase; }
    uint32_t image_size() const { return kImageSize; }
    uint32_t entry_va() const { return kEntryVa; }
    bool contains_va(uint32_t va, size_t bytes = 1) const;
    uint8_t* ptr_from_va(uint32_t va, size_t bytes = 1);
    const uint8_t* ptr_from_va(uint32_t va, size_t bytes = 1) const;
    size_t import_count() const;
    size_t implemented_import_count() const;
    const ImportEntry* find_import(std::string_view dll, std::string_view symbol) const;
private:
    uint8_t* image_{};
};
}
