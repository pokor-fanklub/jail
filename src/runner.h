#pragma once

#include <string>
#include <vector>
#include <unistd.h>

#include "perf.h"
#include "seccomp.h"

namespace jail {

class Runner {
    public:
        Runner(const std::string& exec_name, const std::vector<std::string>& exec_args, Perf& perf, Seccomp& seccomp) : 
            exec_name(exec_name), exec_args(exec_args), perf(perf), seccomp(seccomp) {};

        void run();
    private:
        void forkedChild();
        void forkedMonitor();
        
        pid_t child_pid;
        std::string exec_name;
        std::vector<std::string> exec_args;
        Perf& perf;
        Seccomp& seccomp;
};

};
