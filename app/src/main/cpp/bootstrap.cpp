#include <jni.h>
#include <vulkan/vulkan.h>
#include <dlfcn.h>
#include <sstream>
#include <string>
#include <vector>

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
    out << "Mafia II Android ARM64 Bootstrap v0.1\n\n";
#if defined(__aarch64__)
    out << "CPU ABI: ARM64 OK\n";
#else
    out << "CPU ABI: not ARM64\n";
#endif
    std::string gpu;
    out << "Vulkan: " << (has_vk_device(gpu) ? "OK" : "FAILED") << "\n";
    if (!gpu.empty()) out << "GPU: " << gpu << "\n";
    void* dxvk = dlopen("libdxvk_d3d9.so", RTLD_NOW | RTLD_LOCAL);
    out << "DXVK D3D9 module: " << (dxvk ? "FOUND" : "not bundled yet") << "\n";
    if (dxvk) dlclose(dxvk);
    void* game = dlopen("libmafia2_recomp.so", RTLD_NOW | RTLD_LOCAL);
    out << "Mafia II ARM64 recomp module: " << (game ? "FOUND" : "missing (next milestone)") << "\n\n";
    out << "Raw Mafia2.exe is PE32/i386 and cannot be loaded natively on Android ARM64.\n";
    out << "Next: x86 recompilation/CPU bridge + Win32 ABI, then route D3D9 through DXVK.";
    if (game) dlclose(game);
    return env->NewStringUTF(out.str().c_str());
}
