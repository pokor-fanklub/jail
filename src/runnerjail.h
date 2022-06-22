#pragma once

#include "seccomp.h"
#include "params.h"

#include <string>
#include <vector>

namespace jail {

class RunnerJail {
    public:
        RunnerJail(int pid_pipe_fd, const Params& params, Seccomp& seccomp) 
            : pid_pipe(pid_pipe_fd), params(params), seccomp(seccomp) {}

        static int init_clone_trampoline(void* jail);
        void init_main();

    private:
        void jail_main();
        int getRealChildPid();
        void setupFdsNs(Namespaces& ns);
        void changeFds();

        int pid_pipe;
        
        const Params& params;
        Seccomp& seccomp;
};

};
