#include "timelimit.h"
#include <thread>
#include <chrono>
#include <signal.h>

const unsigned int SAMPLING_MS = 10;

namespace jail {

std::thread TimeLimit::attach() {
    std::thread tl_thread(&jail::TimeLimit::thread_loop, this);
    return tl_thread;
}

void TimeLimit::thread_loop() {
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(SAMPLING_MS));
        
        if (kill(limited_pid, 0)) // check if process is still alive
            return;

        if (!verify_insn_limit()) {
            killed = INSTR_LIM_EXCD;
            kill(limited_pid, SIGKILL);
            return;
        }

        // real time limit is only used as emergency limit, if process manages to block (and not increment instructions)
        if(real_time_enabled && ((uint64_t)time(nullptr) - real_time_start > real_time_limit)) {
            killed = REAL_TIME_EXCD;
            kill(limited_pid, SIGKILL);
            return;
        }
    }
}

void TimeLimit::start_real_time_limit() {
    real_time_enabled = true;
    real_time_start = time(nullptr);
}

bool TimeLimit::verify_insn_limit() {
    return (perf.readInstructions() <= instruction_limit);
}

};