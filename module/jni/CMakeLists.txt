cmake_minimum_required(VERSION 3.22.1)

project(zygiskhook)

# ./libcxx prebuilt
include_directories(${CMAKE_SOURCE_DIR}/libcxx/include)
link_libraries(${CMAKE_SOURCE_DIR}/libcxx/${CMAKE_ANDROID_ARCH_ABI}.a)

# libcxx from gradle/libs.versions.toml
#find_package(cxx REQUIRED CONFIG)
#link_libraries(cxx::cxx)

# libcxx source

# https://github.com/liyafe1997/PlayIntegrityFix
# Dobby source
# git submodule add -- https://github.com/jmpews/Dobby.git ./module/jni/Dobby
add_subdirectory(${CMAKE_SOURCE_DIR}/Dobby)

add_library(${CMAKE_PROJECT_NAME} SHARED ${CMAKE_SOURCE_DIR}/main.cpp)

SET_OPTION(Plugin.Android.BionicLinkerUtil ON)

target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE c_std_23 cxx_std_23)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log dobby_static)
