#include <jni.h>
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include "recomp_runtime.h"

namespace {
bool file_exists(const std::string& p) {
    struct stat st{};
    return !p.empty() && stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool has_vk_device(std::string& name) {
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = "Mafia2Android";
    app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo create{VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO};
    create.pApplicationInfo = &app;
    VkInstance instance = VK_NULL_HANDLE;
    if (vkCreateInstance(&create, nullptr, &instance) != VK_SUCCESS) return false;
    uint32_t count = 0;
    vkEnumeratePhysicalDevices(instance, &count, nullptr);
    std::vector<VkPhysicalDevice> devices(count);
    if (count) vkEnumeratePhysicalDevices(instance, &count, devices.data());
    if (count) {
        VkPhysicalDeviceProperties props{};
        vkGetPhysicalDeviceProperties(devices[0], &props);
        name = props.deviceName;
    }
    vkDestroyInstance(instance, nullptr);
    return count > 0;
}

std::string from_jstring(JNIEnv* env, jstring s) {
    if (!s) return {};
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string out = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return out;
}

std::string lib_state(const char* soname) {
    void* h = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
    if (!h) return "missing";
    dlclose(h);
    return "ready";
}

using RecompEntry = int(*)(const char* game_root);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_m2port_bootstrap_MainActivity_nativeProbe(JNIEnv* env, jclass, jstring root_) {
    const std::string root = from_jstring(env, root_);
    std::ostringstream out;
    out << "Mafia II Android ARM64 Host v0.5\n\n";
#if defined(__aarch64__)
    out << "CPU ABI: ARM64 OK\n";
#else
    out << "CPU ABI: unsupported\n";
#endif

    std::string gpu;
    out << "Vulkan 1.1: " << (has_vk_device(gpu) ? "OK" : "FAILED") << "\n";
    if (!gpu.empty()) out << "GPU: " << gpu << "\n";

    out << "\nGame root:\n" << root << "\n";
    const std::string exe = file_exists(root + "/pc/mafia2.exe") ? root + "/pc/mafia2.exe" : root + "/mafia2.exe";
    out << "mafia2.exe: " << (file_exists(exe) ? "FOUND" : "missing") << "\n";
    if (file_exists(exe)) out << "Executable: " << exe << "\n";
    out << "pc/sds: " << ((file_exists(root + "/pc/sds/config.bin") || file_exists(root + "/pc/sds/tables.sds")) ? "detected" : "not detected") << "\n";

    m2::Runtime rt;
    out << "\nARM64 recomp runtime: " << (rt.ready() ? "OK" : "FAILED") << "\n";
    out << std::hex << std::uppercase << std::setfill('0')
        << "PE image base: 0x" << std::setw(8) << rt.image_base() << "\n"
        << "PE image size: 0x" << std::setw(8) << rt.image_size() << "\n"
        << "Mafia II entry VA: 0x" << std::setw(8) << rt.entry_va() << "\n"
        << std::dec
        << "Import registry: " << rt.import_count() << " entries\n";

    m2::X86State cpu{};
    cpu.esp = m2::kImageBase + m2::kImageSize - 0x1000u;
    cpu.eip = m2::kTestBlockVa;
    const bool pushed = rt.push32(cpu, m2::kHaltVa);
    const auto report = pushed ? rt.dispatch(cpu)
        : m2::DispatchReport{m2::DispatchResult::MemoryFault, 0, cpu.eip};
    const bool dispatch_ok = report.result == m2::DispatchResult::Halted
        && cpu.eax == 0x12345678u && cpu.ebx == 0x12345688u;
    out << "Recomp dispatcher self-test: " << (dispatch_ok ? "PASS" : "FAIL") << "\n";

    out << "\nlibmafia2_recomp.so: " << lib_state("libmafia2_recomp.so") << "\n";
    out << "DXVK D3D9: " << lib_state("libdxvk_d3d9.so") << "\n";
    out << "SDL2: " << lib_state("libSDL2.so") << "\n";

    const bool game = file_exists(exe);
    out << "\nSTATUS: ";
    if (!game) out << "copy your Mafia II PC files into this folder";
    else if (lib_state("libmafia2_recomp.so") != "ready") out << "game files ready; recomp core still required";
    else out << "ready for ARM64 recomp launch";
    return env->NewStringUTF(out.str().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_m2port_bootstrap_MainActivity_nativeStart(JNIEnv* env, jclass, jstring root_) {
    const std::string root = from_jstring(env, root_);
    const std::string exe = file_exists(root + "/pc/mafia2.exe") ? root + "/pc/mafia2.exe" : root + "/mafia2.exe";
    if (!file_exists(exe))
        return env->NewStringUTF("Start blocked: mafia2.exe is missing (expected pc/mafia2.exe or mafia2.exe).");

    void* h = dlopen("libmafia2_recomp.so", RTLD_NOW | RTLD_LOCAL);
    if (!h) {
        std::string msg = "Start blocked: libmafia2_recomp.so is not installed yet. ";
        const char* e = dlerror();
        if (e) msg += e;
        return env->NewStringUTF(msg.c_str());
    }

    auto entry = reinterpret_cast<RecompEntry>(dlsym(h, "mafia2_recomp_main"));
    if (!entry) {
        dlclose(h);
        return env->NewStringUTF("Start blocked: recomp core has no mafia2_recomp_main export.");
    }

    const int rc = entry(root.c_str());
    dlclose(h);
    std::ostringstream out;
    out << "Mafia II recomp core returned " << rc << ".";
    return env->NewStringUTF(out.str().c_str());
}
