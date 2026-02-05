#include <jni.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <android/log.h>
#include <dlfcn.h>
#include <cstdio>   // Missing: for FILE, fopen, fgets, fclose
#include <cstdlib>  // Missing: for strtoull

#define LOG_TAG "VehicleLimitFixer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// Utility to find the base address of a loaded library
uintptr_t get_lib_base(const char* libName) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, libName)) {
            base = (uintptr_t)strtoull(line, NULL, 16);
            break;
        }
    }
    fclose(fp);
    return base;
}

// Memory patcher that handles write protection
void patch_mem(uintptr_t addr, const char* data, size_t size) {
    uintptr_t page_start = addr & ~(getpagesize() - 1);
    // Grant write permissions to the memory page
    mprotect((void*)page_start, getpagesize() * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy((void*)addr, data, size);
    // Restore original permissions (Read + Exec)
    mprotect((void*)page_start, getpagesize() * 2, PROT_READ | PROT_EXEC);
}

extern "C" jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("Plugin Loading: Preparing to patch Vehicle ID Limits...");

    // Find libGTASA.so base address
    uintptr_t gtasa_base = get_lib_base("libGTASA.so");
    
    if (gtasa_base != 0) {
        LOGI("Found libGTASA.so at: 0x%lx", gtasa_base);

        // Offset from your crash log: 0x45B3C8
        // Patching with ARM64 NOP (No Operation): 0x1F 0x20 0x03 0xD5
        uintptr_t crash_addr = gtasa_base + 0x45B3C8;
        patch_mem(crash_addr, "\x1F\x20\x03\xD5", 4);
        
        LOGI("Successfully patched vehicle limit check at 0x%lx", crash_addr);
    } else {
        LOGI("Error: Could not find libGTASA.so base address!");
    }

    return JNI_VERSION_1_6;
}
