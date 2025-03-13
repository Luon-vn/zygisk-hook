cmake_minimum_required(VERSION 3.22)

project(zygiskhook)
# Main source
# SET_OPTION(Plugin.Android.BionicLinkerUtil ON)
add_library(${CMAKE_PROJECT_NAME} SHARED ${CMAKE_SOURCE_DIR}/main.cpp)
target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE c_std_23 cxx_std_23)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log )

# https://github.com/liyafe1997/PlayIntegrityFix

# ./libcxx prebuilt
include_directories(${CMAKE_SOURCE_DIR}/libcxx/include)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/libcxx/${CMAKE_ANDROID_ARCH_ABI}.a)

# ./DobbyHook Prebuilt
# include_directories(${CMAKE_SOURCE_DIR}/DobbyPrebuilt/include)
# link_libraries(${CMAKE_SOURCE_DIR}/DobbyPrebuilt/${CMAKE_ANDROID_ARCH_ABI}.a)

# set(ANDROID_STL "c++_shared") # CXX STL mode for lib
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 23)

# libcxx from gradle/libs.versions.toml
#find_package(cxx REQUIRED CONFIG)
#target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE cxx::cxx)

# DobbyHook source
# git submodule add -- https://github.com/JingMatrix/Dobby.git ./module/jni/Dobby
# add_subdirectory(${CMAKE_SOURCE_DIR}/Dobby)
# target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE dobby_static)

# bytehook
find_package(bytehook REQUIRED CONFIG)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE bytehook::bytehook)

# shadowhook
if((${ANDROID_ABI} STREQUAL "arm64-v8a") OR (${ANDROID_ABI} STREQUAL "armeabi-v7a"))
    find_package(shadowhook REQUIRED CONFIG)
    target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE shadowhook::shadowhook)
endif()
