#pragma once

#include <stdint.h>
#include <string>
#include "timelimit.h"
#include "params.h"

namespace jail {

class Output {
    public:
        Output(const Params& params) : params(params) {};

        void print();
        static void print_sys_err();

        enum Status {
            OK, // Correctly executed
            TLE, // Instruction limit exceeded
            RLE, // Real time limit exceeded
            SYS, // Internal system error
            RE, // Runtime error
            SUS // Suspected of rules violation
        };

        void set_state(uint64_t r_rax, uint64_t pc);
        void set_mem(uint64_t mem);
        void exit_ok(int status);
        void exit_killsig(int sig, bool before_exec);
        void set_instructions(uint64_t instructions);
        void set_time_limit(TimeLimit::KillReason reason);

    private:
        std::string gen_description();
        std::string gen_tip();
        std::string get_sys_name(int sys);

        Status status = OK;

        int return_code = 0;
        uint64_t instruction_count = 0;
        uint64_t memory_used = 0;
        uint64_t state_r_rax = 0, state_pc = 0;
        int signo = -1;
        bool before_exec = false;

        const Params& params;
};

};