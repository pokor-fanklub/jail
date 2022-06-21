#pragma once

#include "seccomp.h"

#include <string>
#include <vector>

namespace jail {

class RunnerJail {
    public:
        RunnerJail(int pid_pipe_fd, std::string& exec_name, std::vector<std::string>& exec_args, Seccomp& seccomp, uint uid, uint gid) 
            : pid_pipe(pid_pipe_fd), exec_name(exec_name), exec_args(exec_args), seccomp(seccomp), uid(uid), gid(gid) {}

        static int init_clone_trampoline(void* jail);
        void init_main();

    private:
        void jail_main();
        int getRealChildPid();

        int pid_pipe;

        std::string& exec_name;
        std::vector<std::string>& exec_args;
        Seccomp& seccomp;
        uint uid, gid;
};

};
