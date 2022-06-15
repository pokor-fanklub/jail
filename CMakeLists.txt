cmake_minimum_required(VERSION 3.10)
project(wa-jail CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -O2")

set(sources ${sources} 
    src/log.cpp
    src/main.cpp
    src/perf.cpp
    src/runner.cpp
    src/seccomp.cpp
)

add_executable(wa-jail ${sources})

target_link_libraries(wa-jail seccomp)