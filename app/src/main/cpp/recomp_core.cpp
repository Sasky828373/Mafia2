#include "recomp_runtime.h"
#include <android/log.h>
#include <sys/stat.h>
#include <string>

#define M2LOG(...) __android_log_print(ANDROID_LOG_INFO, "Mafia2Recomp", __VA_ARGS__)

namespace {
bool exists(const std::string& p) {
    struct stat st{};
    return stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}
}

extern "C" __attribute__((visibility("default")))
int mafia2_recomp_main(const char* game_root) {
    if (!game_root || !*game_root) return -1;
    const std::string root(game_root);
    const std::string exe = exists(root + "/pc/mafia2.exe")
        ? root + "/pc/mafia2.exe" : root + "/mafia2.exe";
    if (!exists(exe)) {
        M2LOG("mafia2.exe not found");
        return -2;
    }

    m2::Runtime rt;
    if (!rt.ready()) return -3;

    m2::X86State cpu{};
    cpu.eip = rt.entry_va();
    cpu.esp = m2::kImageBase + m2::kImageSize - 0x1000u;
    if (!rt.push32(cpu, m2::kHaltVa)) return -4;

    M2LOG("ARM64 recomp core start: exe=%s entry=0x%08X", exe.c_str(), rt.entry_va());
    const auto report = rt.dispatch(cpu, 1000000);
    M2LOG("dispatcher result=%d steps=%u eip=0x%08X",
          static_cast<int>(report.result), report.steps, report.last_eip);

    switch (report.result) {
        case m2::DispatchResult::Halted: return 0;
        case m2::DispatchResult::MissingBlock: return 10;
        case m2::DispatchResult::MemoryFault: return 11;
        case m2::DispatchResult::StepLimit: return 12;
    }
    return 13;
}
