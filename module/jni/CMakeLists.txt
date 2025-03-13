cmake_minimum_required(VERSION 3.22.1)

project(zygiskhook)
# https://github.com/liyafe1997/PlayIntegrityFix

# ./libcxx prebuilt
# include_directories(${CMAKE_SOURCE_DIR}/libcxx/include)
# link_libraries(${CMAKE_SOURCE_DIR}/libcxx/${CMAKE_ANDROID_ARCH_ABI}.a)

# ./Dobby Prebuilt
include_directories(${CMAKE_SOURCE_DIR}/DobbyPrebuilt/include)
add_library(DobbyLib STATIC IMPORTED)
set_target_properties(DobbyLib PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/DobbyPrebuilt/${ANDROID_ABI}.a)

set(ANDROID_STL "c++_shared") # CXX STL mode for lib
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_C_STANDARD 23)

# libcxx from gradle/libs.versions.toml
#find_package(cxx REQUIRED CONFIG)
#link_libraries(cxx::cxx)

# Dobby source
# git submodule add -- https://github.com/JingMatrix/Dobby.git ./module/jni/Dobby
# add_subdirectory(${CMAKE_SOURCE_DIR}/Dobby)
# Dobby source
# target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log dobby_static)

# Main source
# SET_OPTION(Plugin.Android.BionicLinkerUtil ON)
add_library(${CMAKE_PROJECT_NAME} SHARED ${CMAKE_SOURCE_DIR}/main.cpp)
target_compile_features(${CMAKE_PROJECT_NAME} PRIVATE c_std_23 cxx_std_23)

# Dobby Prebuilt
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log DobbyLib)
