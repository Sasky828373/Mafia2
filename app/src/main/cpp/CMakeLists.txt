cmake_minimum_required(VERSION 3.22.1)
project(m2bootstrap LANGUAGES C CXX)

find_library(log-lib log)
find_library(dl-lib dl)
find_library(vulkan-lib vulkan)

add_library(m2bootstrap SHARED bootstrap.cpp recomp_runtime.cpp)
target_compile_features(m2bootstrap PRIVATE cxx_std_20)
target_compile_options(m2bootstrap PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(m2bootstrap PRIVATE ${log-lib} ${dl-lib} ${vulkan-lib})

# Separate ARM64 recomp core loaded by the Android host.
add_library(mafia2_recomp SHARED recomp_core.cpp recomp_runtime.cpp)
target_compile_features(mafia2_recomp PRIVATE cxx_std_20)
target_compile_options(mafia2_recomp PRIVATE -O3 -DNDEBUG -fvisibility=hidden)
target_link_libraries(mafia2_recomp PRIVATE ${log-lib} ${dl-lib})
