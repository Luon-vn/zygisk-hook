#include <jni.h>
#include <string>
#include "zygisk.h"
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

// #include "zygisk.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

#define LOG_TAG "ZygiskHook"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ==== Hook ====

void *(*orig__dlopen)(const char *filename, int flags);
void *my_dlopen(const char *filename, int flags) {
    LOGE("dlopen: %s", filename);
    return orig__dlopen(filename, flags);
}

void *(*orig__dlsym)(void *handle, const char *name);
void *my_dlsym(void *handle, const char *name) {
    LOGE("dlsym: %s", name);
    return orig__dlsym(handle, name);
}

void *(*orig_android_dlopen_ext)(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info);
void *my_android_dlopen_ext(const char *_Nullable __filename, int __flags, const android_dlextinfo *_Nullable __info) {
    LOGE("android_dlopen_ext: %s flags: %08x", __filename, __flags);

    return orig_android_dlopen_ext(__filename, __flags, __info);
}

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
        if (do_hook) {
            //hook dlopen
            api->pltHookRegister(".*", "dlopen", (void *) my_dlopen, (void **) &orig__dlopen);
            api->pltHookRegister(".*", "dlsym", (void *) my_dlsym, (void **) &orig__dlsym);
            //hook android_dlopen_ext
            // api->pltHookRegister(".*", "android_dlopen_ext", (void *) my_android_dlopen_ext, (void **) &orig_android_dlopen_ext);
            api->pltHookCommit();
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    Api *api;
    JNIEnv *env;
    bool do_hook;

    void preSpecialize(const char *package_name, const char *app_data_dir) {
        int fd = api->connectCompanion();
        send_string(fd, package_name);
        send_string(fd, app_data_dir);

        std::string buf = read_string(fd);
        if (buf == "0") {
            // Since we do not hook any functions, we should let Zygisk dlclose ourselves
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        do_hook = true;
    }

};

// 
static void companion_handler(int fd) {
    std::string package_name = read_string(fd);
    LOGE("companion: package %s", package_name.c_str());
    std::string app_data_dir = read_string(fd);
    LOGE("companion: datadir %s", app_data_dir.c_str());

    std::string config_file = "/data/local/tmp/zygisk.hook/" + package_name + ".txt";

    if (std::filesystem::exists(config_file)) {
        std::string hook = readFirstLine(config_file.c_str());
        if (!hook.empty()) {
            LOGE("companion: do hook %s", package_name.c_str());
            send_string(fd, "1");
            return;
        }
    }

    LOGE("companion: dont hook %s", package_name.c_str());
    send_string(fd, "0");
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(ZygiskHook)
REGISTER_ZYGISK_COMPANION(companion_handler)
