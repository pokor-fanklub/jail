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

        static void killNS();
    private:
        void monitorProcess();

        void setPRLimits();
        void setIntHandler(bool enable);
        int pidResources();

        void _setPRLimit(__rlimit_resource resource, uint64_t limit);
        
        pid_t ns_init_pid = -1;
        pid_t jail_pid = -1;
        int pid_pipe_fd;
        std::string exec_name;
        std::vector<std::string> exec_args;
        limits rlimits;
        Perf& perf;
        Seccomp& seccomp;
        uint jail_uid = 65534; // nobody:nogroup
        uint jail_gid = 65534;
};

};
