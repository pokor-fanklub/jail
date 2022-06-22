#pragma once

#include <inttypes.h>
#include <sys/resource.h>

struct limits {
    uint64_t instructions = 1*2e9;
    uint64_t real_time = 10; // emergency limit for jail wall clock run time, in case if process blocks 
    uint64_t total_memory_kb = 100*1024; // data + heap + stack
    uint64_t stack_kb = RLIM64_INFINITY; // separate limit for stack
    uint64_t per_file_kb = 100;
    uint64_t open_files = 3; // stdin + stdout + stderr
};