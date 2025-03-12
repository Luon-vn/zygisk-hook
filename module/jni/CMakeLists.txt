cmake_minimum_required(VERSION 3.4.1)

project("zygiskhook")

add_subdirectory(libcxx)

add_library(${CMAKE_PROJECT_NAME} SHARED main.cpp)

target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log libcxx)

target_compile_options(${CMAKE_PROJECT_NAME} PRIVATE
    -std=c++17
    -fno-exceptions
    -fno-rtti
    -fvisibility=hidden
    -fvisibility-inlines-hidden
)