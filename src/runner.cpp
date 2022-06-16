#include "runner.h"
#include "log.h"
#include "timelimit.h"

#include <iostream>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <assert.h>

#include <syscall.h>

namespace jail {

void Runner::run() {
    pid_t pid = fork();
    
    if(pid < 0)
        jail::panic("Runner fork failed");
    
    if(pid == 0) {
        forkChild();
    } else {
        std::cout<<"pid"<<pid<<'\n';
        Runner::child_pid = pid;
        forkMonitor();
    }
}

void Runner::forkChild() {
    assert(ptrace(PTRACE_TRACEME,0,0,0) >= 0);
    const char* c_argv[Runner::exec_args.size()+2];
    c_argv[0] = Runner::exec_name.c_str();
    for(size_t i = 0; i < Runner::exec_args.size(); i++)
        c_argv[i+1] = Runner::exec_args[i].c_str();
    c_argv[2] = nullptr;
    

    Runner::seccomp.attach();
    execv(Runner::exec_name.c_str(), (char*const*) c_argv);
    std::cerr<<errno;
    jail::panic("execv failed");
}

void Runner::forkMonitor() {
    int wait_s;

    // setup TimeLimit
    TimeLimit time_limit(Runner::child_pid, 1000000000, Runner::perf);
    std::thread time_limit_thread = time_limit.attach();

    // initial stop from PTRACE_TRACEME
    pid_t rc = waitpid(Runner::child_pid, &wait_s, 0);
    if(rc < 0 || WIFSTOPPED(wait_s) != 1)
        jail::panic("wait failed");
    // this option creates additional event just before exit and allows to examine registers
    // change options only when stopped
    ptrace(PTRACE_SETOPTIONS, Runner::child_pid, 0, PTRACE_O_TRACEEXIT);
    
    rc = ptrace(PTRACE_CONT, Runner::child_pid, 0, 0);
    if(rc < 0)
        jail::panic("initial ptrace_cont failed");
    std::cout<<"resuming after initial stop\n";

    for(;;) {
        pid_t rc = waitpid(Runner::child_pid, &wait_s, 0);
        if(rc < 0)
            jail::panic("wait failed");
            
        std::cout<<"wait status exit:"<<WIFEXITED(wait_s)<<" sig:"<<WIFSIGNALED(wait_s)<<" stop:"<<WIFSTOPPED(wait_s)<<'\n';
        std::cout<<"codes s"<<WSTOPSIG(wait_s)<<" t"<<WTERMSIG(wait_s)<<'\n';

        // both of those are terminating signals and don't allow PTRACE_CONT
        if(WIFEXITED(wait_s) || WIFSIGNALED(wait_s)) {
            if(WIFSIGNALED(wait_s))
                std::cout<<"killed by singal!\n";
            else
                std::cout<<"exited normally\n";
            break;
        }
            
        user_regs_struct uregs;
        long ret = ptrace(PTRACE_GETREGS, Runner::child_pid, 0, &uregs); // this is not available when exit status is set
        if(ret < 0)
            jail::panic("ptrace_getregs failed");
        std::cerr<<"regs: rax="<<uregs.rax<<" orax="<<uregs.orig_rax<<'\n';

        ret = ptrace(PTRACE_CONT, Runner::child_pid, 0, 0);
        if(ret < 0)
            jail::panic("ptrace_cont failed");
    }
    std::cout<<"exited with code: "<<WEXITSTATUS(wait_s)<<'\n';

    time_limit_thread.detach(); // detach timelimt thread to finish on its own
    
    if(time_limit.get_killed())
        std::cout<<"killed by tlthread\n";
    if(!time_limit.verify())
        std::cout<<"tle\n";
}

};
