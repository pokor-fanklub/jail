#pragma once

#include <string>
#include <vector>
#include <unistd.h>

#include "perf.h"
#include "seccomp.h"
#include "limits.h"
#include "params.h"

namespace jail {

class Runner {
    public:
        Runner(const Params& params) : params(params), seccomp(Seccomp(params.sec_rs)) {};

        void run();

        static void killNS();
    private:
        void monitorProcess();

        void setPRLimits();
        void setIntHandler(bool enable);
        int pidResources();

        void _setPRLimit(__rlimit_resource resource, uint64_t limit);
        
        const Params& params;
        pid_t ns_init_pid = -1;
        pid_t jail_pid = -1;
        int pid_pipe_fd;

        Perf perf;
        Seccomp seccomp;
};

};
