#pragma once

#include "perf.h"

#include <unistd.h>
#include <thread>
#include <atomic>

namespace jail {

class TimeLimit {
    public:
        TimeLimit(pid_t limit_pid, uint64_t instruction_limit, uint64_t real_time_limit_s, Perf& perf) : 
            limited_pid(limit_pid), instruction_limit(instruction_limit), real_time_limit(real_time_limit_s), perf(perf) {}

        enum KillReason {
            NONE = 0,
            INSTR_LIM_EXCD,
            REAL_TIME_EXCD
        };

        std::thread attach();
        bool verify_insn_limit();
        std::atomic<KillReason>& get_killed() { return killed; };
    private:
        pid_t limited_pid;
        uint64_t instruction_limit;
        uint64_t real_time_limit;
        Perf& perf;
        std::atomic<KillReason> killed {NONE};
        time_t real_time_start;

        void thread_loop();
};

};