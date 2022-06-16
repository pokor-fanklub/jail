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

        if (!verify()) {
            killed = true;
            kill(limited_pid, SIGKILL);
            return;
        }
    }
}

bool TimeLimit::verify() {
    return (perf.readInstructions() <= instruction_limit);
}

};