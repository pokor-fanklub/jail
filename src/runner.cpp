#include "runner.h"
#include "log.h"
#include "timelimit.h"

#include <iostream>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/resource.h>
#include <assert.h>

#include <syscall.h>

static pid_t sighandler_kill_pid;
void sigint_handler(int signo) {
    std::cout<<" Recived termination signal. Killing child process\n";
    int pid = sighandler_kill_pid;
    if(kill(pid, 0) == 0)
        kill(pid, SIGKILL);
    jail::panic("Interrupted");
}

namespace jail {

void Runner::run() {
    pid_t pid = fork();
    
    if(pid < 0)
        jail::panic("Runner fork failed");
    
    if(pid == 0) {
        forkedChild();
    } else {
        std::cout<<"pid"<<pid<<'\n';
        Runner::child_pid = pid;
        forkedMonitor();
    }
}

void Runner::forkedChild() {
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

void Runner::forkedMonitor() {
    int wait_s;

    // register sigproc
    sighandler_kill_pid = Runner::child_pid;
    struct sigaction sigact;
    sigact.sa_handler = sigint_handler;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
    
    // setup TimeLimit
    TimeLimit time_limit(Runner::child_pid, 1000000000000000, Runner::perf);
    std::thread time_limit_thread = time_limit.attach();
        
    // initial stop from PTRACE_TRACEME
    pid_t rc = waitpid(Runner::child_pid, &wait_s, 0);
    if(rc < 0 || WIFSTOPPED(wait_s) != 1)
        jail::panic("wait failed");
    // this option creates additional event just before exit and allows to examine registers
    // change options only when stopped
    rc = ptrace(PTRACE_SETOPTIONS, Runner::child_pid, 0, PTRACE_O_TRACEEXIT);
    if(rc < 0)
        jail::panic("prace exitkill failed");

    // setup prlimit
    rlimit64 rlim;
    rlim.rlim_cur = 100000000; // soft limit
    rlim.rlim_max = 100000000; // hard limit
    int rcx = prlimit64(Runner::child_pid, RLIMIT_AS, &rlim, nullptr);
    if(rcx < 0)
        jail::panic("prlimit fail");
    rlimit64 nrl = {RLIM_INFINITY, RLIM_INFINITY};
    rcx = prlimit64(Runner::child_pid, RLIMIT_STACK, &nrl, nullptr);
    if(rcx < 0)
        jail::panic("prlimit fail");
    rcx = prlimit64(Runner::child_pid, RLIMIT_FSIZE, &rlim, nullptr);
    nrl = {3+2, 3+2};
    rcx = prlimit64(Runner::child_pid, RLIMIT_NOFILE,&nrl, nullptr);
    nrl = {0,0};
    rcx = prlimit64(Runner::child_pid, RLIMIT_MEMLOCK,&nrl, nullptr);
    rcx = prlimit64(Runner::child_pid, RLIMIT_NPROC,&nrl, nullptr);
    // set real time limit in case of process block/pause
    nrl = {10, 10};
    rcx = prlimit64(Runner::child_pid, RLIMIT_CPU, &nrl, nullptr);
    
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

        rusage ru;
        getrusage(RUSAGE_CHILDREN, &ru);
        std::cout<<"rusage"<<ru.ru_maxrss*1024<<" realruntime"<<ru.ru_utime.tv_sec+ru.ru_stime.tv_sec<<"\n";

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
        std::cerr<<"regs: rax="<<uregs.rax<<" orax="<<uregs.orig_rax<<" rip(pc)="<<uregs.rip<<'\n';
        
        ret = ptrace(PTRACE_CONT, Runner::child_pid, 0, WSTOPSIG(wait_s));
        if(ret < 0)
            jail::panic("ptrace_cont failed");
    }
    std::cout<<"exited with code: "<<WEXITSTATUS(wait_s)<<'\n';

    sigact.sa_handler = SIG_DFL;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    time_limit_thread.detach(); // detach timelimt thread to finish on its own
    
    if(time_limit.get_killed())
        std::cout<<"killed by tlthread\n";
    if(!time_limit.verify())
        std::cout<<"tle\n";
}

};
