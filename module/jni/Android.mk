LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := zygiskhook
LOCAL_SRC_FILES := main.cpp
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

# git submodule add -- https://github.com/topjohnwu/libcxx.git ./module/jni/libcxx
LOCAL_STATIC_LIBRARIES += libcxx
include jni/libcxx/Android.mk

LOCAL_SHARED_LIBRARIES += shadowhook
$(call import-module,prefab/shadowhook)

# If you do not want to use libc++, link to system stdc++
# so that you can at least call the new operator in your code

# include $(CLEAR_VARS)
# LOCAL_MODULE := example
# LOCAL_SRC_FILES := example.cpp
# LOCAL_LDLIBS := -llog -lstdc++
# include $(BUILD_SHARED_LIBRARY)
