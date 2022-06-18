#pragma once

#include <string>
#include <vector>
#include <unistd.h>

#include "perf.h"
#include "seccomp.h"
#include "limits.h"

namespace jail {

class Runner {
    public:
        Runner(const std::string& exec_name, const std::vector<std::string>& exec_args, limits& rlimits, Perf& perf, Seccomp& seccomp) : 
            exec_name(exec_name), exec_args(exec_args), rlimits(rlimits), perf(perf), seccomp(seccomp) {};

        void run();
    private:
        void forkedChild();
        void forkedMonitor();

        void setPRLimits();
        void setIntHandler(bool enable);

        void _setPRLimit(__rlimit_resource resource, uint64_t limit);
        
        pid_t child_pid;
        std::string exec_name;
        std::vector<std::string> exec_args;
        limits rlimits;
        Perf& perf;
        Seccomp& seccomp;
};

};
