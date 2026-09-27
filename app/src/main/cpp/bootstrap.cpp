#include <jni.h>
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include "recomp_runtime.h"

static bool has_vk_device(std::string& name) {
    VkApplicationInfo app{VK_STRUCTURE_TYPE_APPLICATION_INFO};
    app.pApplicationName = "Mafia2Bootstrap";
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

extern "C" JNIEXPORT jstring JNICALL
Java_com_m2port_bootstrap_MainActivity_nativeProbe(JNIEnv* env, jclass) {
    std::ostringstream out;
    out << "Mafia II Android ARM64 Bootstrap v0.2\n\n";
#if defined(__aarch64__)
    out << "CPU ABI: ARM64 OK\n";
#else
    out << "CPU ABI: not ARM64\n";
#endif
    std::string gpu;
    out << "Vulkan: " << (has_vk_device(gpu) ? "OK" : "FAILED") << "\n";
    if (!gpu.empty()) out << "GPU: " << gpu << "\n\n";

    m2::Runtime rt;
    out << "Recomp memory arena: " << (rt.ready() ? "OK" : "FAILED") << "\n";
    out << std::hex << std::uppercase << std::setfill('0');
    out << "PE image base: 0x" << std::setw(8) << rt.image_base() << "\n";
    out << "PE image size: 0x" << std::setw(8) << rt.image_size() << "\n";
    out << "Mafia II entry VA: 0x" << std::setw(8) << rt.entry_va() << "\n";
    out << std::dec;
    out << "x86 CPU state: " << sizeof(m2::X86State) << " bytes\n";
    out << "Import registry: " << rt.import_count() << " seed entries\n";

    void* dxvk = dlopen("libdxvk_d3d9.so", RTLD_NOW | RTLD_LOCAL);
    out << "DXVK D3D9 backend: " << (dxvk ? "FOUND" : "pending") << "\n";
    if (dxvk) dlclose(dxvk);

    out << "\nPhase 0.2: runtime foundation only.\n";
    out << "No x86 game instructions are executed yet.\n";
    out << "Next: generated import census + translated code-block dispatcher.";
    return env->NewStringUTF(out.str().c_str());
}
