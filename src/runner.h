#pragma once

#include <string>
#include <vector>
#include <unistd.h>

#include "seccomp.h"

namespace jail {

class Runner {
    public:
        Runner(const std::string& exec_name, const std::vector<std::string>& exec_args, Seccomp& seccomp) : 
            exec_name(exec_name), exec_args(exec_args), seccomp(seccomp) {};

        void run();
    private:
        void forkChild();
        void forkMonitor();
        
        pid_t child_pid;
        std::string exec_name;
        std::vector<std::string> exec_args;
        Seccomp seccomp;
};

};
