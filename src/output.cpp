#include "output.h"

#include <sstream>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <sys/syscall.h>
#include "signal.h"

namespace jail {

void Output::print() {
    std::stringstream out;
    out << "{\n";
    static const std::string stat_str[] = {"OK", "TLE", "RLE", "SYS", "RE", "SUS"}; 
    out << "\"status\": \""<<stat_str[Output::status]<<"\",\n";
    out << "\"description\": \""<<gen_description()<<"\",\n";
    out << "\"instuctions\": "<<Output::instruction_count<<",\n";
    out << "\"memory\": "<<Output::memory_used<<"\n";
    out << "}\n";
    std::cout<<out.str();
}

void Output::print_sys_err() {
    std::stringstream out;
    out << "{\n";
    out << "\"status\": \"SYS\",\n";
    out << "\"description\": \"Internal system error (panic)\",\n";
    out << "\"instuctions\": 0,\n";
    out << "\"memory\": 0\n";
    out << "}\n";
    std::cout<<out.str();
}

std::string Output::gen_description() {
    if (status == RE) {
        std::stringstream ret;
        if(return_code)
            ret << "Non-zero exit code: "<<return_code;    
        else if(before_exec && Output::signo == SIGSEGV)
            ret << "Memory limit exceeded by static data";
        else if((Output::signo == SIGSEGV || Output::signo == SIGABRT) 
                && Output::memory_used >= params.rlimits.total_memory_kb)
            ret << "Memory limit exceeded (killed by SIG"<<sigabbrev_np(Output::signo)<<")";
        else if(Output::signo == SIGABRT 
                && (double)params.rlimits.total_memory_kb/(double)Output::memory_used <= 1.05f)
            ret << "Killed by SIGABRT (probably memory limit exceeded)";
        else
            ret << "Killed by signal: SIG"<<sigabbrev_np(Output::signo);
        return ret.str();
    }
    if (status == SUS) {
        std::stringstream ret;
        ret << "Illegal syscall: "<<get_sys_name(Output::state_r_rax);
        return ret.str();
    }
    return "";
}

std::string Output::get_sys_name(int sys) {
    // TODO
    std::stringstream ret;
    ret<<sys;
    return ret.str();
}

void Output::set_state(uint64_t r_rax, uint64_t pc) {
    Output::state_r_rax = r_rax;
    Output::state_pc = pc;
}

void Output::set_mem(uint64_t mem) {
    Output::memory_used = mem;
}

void Output::exit_ok(int status) {
    Output::return_code = status;
    if(!status)
        Output::status = OK;
    else
        Output::status = RE;
}

void Output::exit_killsig(int sig, bool before_exec) {
    Output::signo = sig;
    Output::before_exec = before_exec;

    if(sig == SIGSYS)
        Output::status = SUS;
    else
        Output::status = RE;
}

void Output::set_instructions(uint64_t instructions) {
    Output::instruction_count = instructions;
}

void Output::set_time_limit(TimeLimit::KillReason reason) {
    if(reason == TimeLimit::KillReason::INSTR_LIM_EXCD) {
        Output::status = TLE;
    } else if (reason == TimeLimit::KillReason::REAL_TIME_EXCD) {
        Output::status = RLE;
    }
}

};