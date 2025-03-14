#include <jni.h>
#include <sys/system_properties.h>
#include <android/asset_manager.h>
#include <string>
#include "zygisk.h"
// #include "zygisk.hpp"
#include <android/log.h>
#include <dlfcn.h>
#include <android/dlext.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <sys/mman.h>
#include <cstdlib>
#include <pthread.h>
#include <cstring>
// #include "dobby.h"
#include "shadowhook.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define TARGET_LIB "libdexprotectorx.so"
#define LOG_TAG "ZygiskHook"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Utils

static std::string readFirstLine(const char *filename) {
    std::ifstream in_file(filename);
    std::string firstLine;
    if (in_file.is_open()) {
        std::getline(in_file, firstLine);
        in_file.close();
    }
    return firstLine;
}

static void writeLine(const char *filename, const char *line) {
    std::ofstream out_file(filename);
    if (out_file.is_open()) {
        out_file << line;
        out_file.close();
    }
}

static void send_string(int fd, const char *str) {
    int len = 0;
    if (str) {
        len = strlen(str);
    }
    write(fd, &len, sizeof(len));
    write(fd, str, len);
}

static std::string read_string(int fd)
{
    int len = 0;
    int r = read(fd, &len, sizeof(len));
    if (r <= 0) {
        return "";
    }
    if (len <= 0) {
        return "";
    }
    char buf[1024];
    read(fd, buf, len);
    buf[len] = '\0';
    return buf;
}

// ==== Hook ====
typedef void (*T_Callback)(void *, const char *, const char *, uint32_t);
static T_Callback o_callback = nullptr;
static void (*orig_system_property_read_callback)(prop_info *, T_Callback, void *) = nullptr;
static void modify_callback(void *cookie, const char *name, const char *value, uint32_t serial) {
    if (!cookie || !name || !value || !o_callback) return;

    const char *oldValue = value;

    std::string_view prop(name);

    LOGE("modify_callback[%s]: %s", name, oldValue);
    return o_callback(cookie, name, value, serial);
}
static void my_system_property_read_callback(prop_info *pi, T_Callback callback, void *cookie) {
    if (pi && callback && cookie) o_callback = callback;
    return orig_system_property_read_callback(pi, modify_callback, cookie);
}
static bool hook_system_property_read_callback() {
    if (shadowhook_hook_sym_name(nullptr, "__system_property_read_callback", (void *) my_system_property_read_callback, (void **) &orig_system_property_read_callback) != NULL) {
        LOGE("hook __system_property_read_callback successful");
        return true;
    }
    LOGE("hook __system_property_read_callback failed!");
    return false;
}

void *(*orig_lib_func)(void *a1, void *a2, int a3);
void *my_lib_func(void *a1, void *a2, int a3) {
    void* ret = orig_lib_func(a1, a2, a3);
    LOGE("lib_func: %s", (char *)ret);
    return ret;
}

void *(*orig_open_2)(const char *file, int oflag);
void *my_open_2(const char *file, int oflag) {
    LOGE("open_2: %s %d", file, oflag);
    return orig_open_2(file, oflag);
}

void *(*orig_kill)(pid_t pid, int sig);
void *my_kill(pid_t pid, int sig) {
    LOGE("kill: %d flags: %d", pid, sig);
    return orig_kill(pid, sig);
}

static unsigned long libso_base_addr = 0;
static void* libso_handle = nullptr;

void *(*orig_dlopen)(const char *filename, int flags);
void *my_dlopen(const char *filename, int flags) {
    LOGE("dlopen: %s flags: %08x", filename, flags);

    void* handle = orig_dlopen(filename, flags);
    /*
    if(!libso_handle){
        if(strstr(filename, TARGET_LIB)){
            libso_handle = handle;
            LOGE("libso handle %lx", (long)libso_handle);

            void *exportedFunc = DobbySymbolResolver(TARGET_LIB, "JNI_OnLoad");
            if (exportedFunc != nullptr) {
                LOGE("libso exported func addr %lx", exportedFunc);
            }

            if (NULL != shadowhook_hook_sym_name((void *)((unsigned long)exportedFunc+93208), (void *) my_lib_func, (void **) &orig_lib_func)) {
                LOGE("libso hooked func addr %lx", (unsigned long)exportedFunc+93208);
            }

            sleep(5);
        }
    }
    // */
    return handle;
}

void *(*orig_dlsym)(void *handle, const char *name);
void *my_dlsym(void *handle, const char *name) {
    LOGE("dlsym: %s", name);
    return orig_dlsym(handle, name);
}

AAsset* (*orig_AAssetManager_open)(AAssetManager* mgr, const char* filename, int mode) = nullptr;
AAsset* my_AAssetManager_open(AAssetManager* mgr, const char* filename, int mode) {
    // LOGE("AAssetManager_open: %s %d", filename, mode);
    AAsset* asset = orig_AAssetManager_open(mgr, filename, mode);
    return asset;
}

void *(*orig_android_dlopen_ext)(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info);
void *my_android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info) {
    LOGE("android_dlopen_ext: %s flags: %08x", __filename, __flags);

    void* handle = orig_android_dlopen_ext(__filename, __flags, __info);
    // /*
    if(!libso_handle){
        if(strstr(__filename, TARGET_LIB)){
            libso_handle = handle;
            LOGE("libso handle %lx", (long)libso_handle);

            void *exportedFunc = dlsym(handle, "JNI_OnLoad");
            if (exportedFunc != nullptr) {
                LOGE("libso exported func addr %lx", exportedFunc);
            }

            if (NULL != shadowhook_hook_sym_addr((void *)((unsigned long)exportedFunc+93208), (void *) my_lib_func, (void **) &orig_lib_func)) {
                LOGE("libso hooked func addr %lx", (unsigned long)exportedFunc+93208);
            }

            sleep(5);
        }
    }
    // */
    return handle;
}

// /*
void *hack_thread(void *arg) {
    LOGE("hack thread: %d", gettid());
    srand(time(nullptr));

    // wait for libso loaded
    LOGE("detect libso %lx, start sleep", libso_base_addr);

    while (true) {
        sleep(2);
    }
}
// */

// Module
class ZygiskHook : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        do_hook = false;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto app_data_dir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        if (!app_data_dir) {
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        auto package_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!package_name) {
            env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        preSpecialize(package_name, app_data_dir);

        env->ReleaseStringUTFChars(args->app_data_dir, app_data_dir);
        env->ReleaseStringUTFChars(args->nice_name, package_name);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        // LOGE("start postAppSpecialize");
        if (do_hook) {
            LOGE("module: start hooking");
            
            // zygisk hook, maybe missing some call, duno @@
            // api->pltHookRegister(".*", "dlopen", (void *) my_dlopen, (void **) &orig_dlopen);
            // api->pltHookRegister(".*", "dlsym", (void *) my_dlsym, (void **) &orig_dlsym);
            //hook android_dlopen_ext
            // api->pltHookRegister(".*", "android_dlopen_ext", (void *) my_android_dlopen_ext, (void **) &orig_android_dlopen_ext);
            // api->pltHookRegister(".*", "__open_2", (void *) my_open_2, (void **) &orig_open_2);
            // api->pltHookCommit();

            // dobby hook
            shadowhook_hook_sym_name(nullptr, "kill", (void *) my_kill, (void **) &orig_kill);
            shadowhook_hook_sym_name(nullptr, "dlopen", (void *) my_dlopen, (void **) &orig_dlopen);
            shadowhook_hook_sym_name(nullptr, "dlsym", (void *) my_dlsym, (void **) &orig_dlsym);
            shadowhook_hook_sym_name(nullptr, "android_dlopen_ext", (void *) my_android_dlopen_ext, (void **) &orig_android_dlopen_ext);
            shadowhook_hook_sym_name("libandroid.so", "AAssetManager_open", (void *) my_AAssetManager_open, (void **) &orig_AAssetManager_open);
            // hook_system_property_read_callback();
            // int ret;
            // pthread_t ntid;
            // if ((ret = pthread_create(&ntid, nullptr, hack_thread, nullptr))) {
            //     LOGE("can't create thread: %s\n", strerror(ret));
            // }

            // sleep(2); // works!

            // dlclose this zygisk module
            // api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        LOGE("start preServerSpecialize");
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api;
    JNIEnv *env;
    bool do_hook;

    void preSpecialize(const char *package_name, const char *app_data_dir) {
        // LOGE("start preSpecialize %s", package_name);
        int fd = api->connectCompanion();
        send_string(fd, package_name);
        send_string(fd, app_data_dir);

        // LOGE("module: readstring");
        std::string buf = read_string(fd);

        // LOGE("module: receive %s", buf.c_str());
        if (buf == "0") {
            // Since we do not hook any functions, we should let Zygisk dlclose ourselves
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        LOGE("module: do hook %s", package_name);
        do_hook = true;
    }

};

// 
static void companion_handler(int fd) {
    // LOGE("start companion_handler");
    std::string package_name = read_string(fd);
    // LOGE("companion: package %s", package_name.c_str());
    std::string app_data_dir = read_string(fd);
    // LOGE("companion: datadir %s", app_data_dir.c_str());

    std::string config_file = "/data/local/tmp/zygisk.hook/" + package_name + ".txt";

    if (std::filesystem::exists(config_file)) {
        std::string hook = readFirstLine(config_file.c_str());
        if (!hook.empty()) {
            LOGE("\n\n===========================\ncompanion: do hook %s", package_name.c_str());
            send_string(fd, "1");
            return;
        }
    }

    // LOGE("companion: dont hook %s", package_name.c_str());
    send_string(fd, "0");
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(ZygiskHook)
REGISTER_ZYGISK_COMPANION(companion_handler)
