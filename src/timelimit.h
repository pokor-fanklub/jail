#pragma once

#include "perf.h"

#include <unistd.h>
#include <thread>
#include <atomic>

namespace jail {

class TimeLimit {
    public:
        TimeLimit(pid_t limit_pid, uint64_t instruction_limit, Perf& perf) : 
            limited_pid(limit_pid), instruction_limit(instruction_limit), perf(perf) {}

        std::thread attach();
        bool verify();
        std::atomic<bool>& get_killed() { return killed; };
    private:
        pid_t limited_pid;
        uint64_t instruction_limit;
        Perf& perf;
        std::atomic<bool> killed {false};

        void thread_loop();
};

};