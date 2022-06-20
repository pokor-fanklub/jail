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
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/prctl.h>

static pid_t static_child_pid = -1;
void sigint_handler(int signo);
extern char* our_stack;

namespace jail {

int Runner::clone_trampoline(void* arg) {
    reinterpret_cast<jail::Runner*>(arg)->forkedChild();
    jail::panic("returned to trampoline");
}

void Runner::run() {
    char* stack = (char*)malloc(1024*1024);
    int pid = clone(clone_trampoline, stack+(1024*1024), SIGCHLD|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWPID, this);
    if(pid < 0)
        jail::panic("clone failed");

    std::cout<<"pid"<<pid<<'\n';
    Runner::child_pid = pid;
    static_child_pid = pid;
    forkedMonitor();
    free(stack);
}

void Runner::forkedChild() {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    int rc = ptrace(PTRACE_TRACEME,0,0,0);
    if(rc < 0)
        jail::panic("ptrace traceme failed");

    const char* c_argv[Runner::exec_args.size()+2];
    c_argv[0] = Runner::exec_name.c_str();
    for(size_t i = 0; i < Runner::exec_args.size(); i++)
        c_argv[i+1] = Runner::exec_args[i].c_str();
    c_argv[2] = nullptr;
    printf("c_argv %s.%s.%d\n", Runner::exec_name.c_str(), c_argv[1], Runner::child_pid);
   
    //assert(false);
    assert(mount(nullptr, "/", nullptr, MS_PRIVATE|MS_REC, nullptr) == 0);
    assert(mount("jail/", "jail/", NULL, MS_BIND, NULL) == 0);
    assert(mount("jinp/", "jail/inp/", NULL, MS_BIND, NULL) == 0);
    assert(mount("jinp/", "jail/inp/", NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL) == 0);
    assert(mount(exec_name.c_str(), "jail/exe", NULL, MS_BIND, NULL) == 0);
    assert(!chdir("jail"));
    assert(!syscall(SYS_pivot_root, ".", "."));
    assert(!umount2(".", MNT_DETACH));
    assert(!setresgid(65534, 65534, 65534));
    assert(!setresuid(65534, 65534, 65534));
    
    Runner::seccomp.attach();
    
    execv(/*exec_name.c_str()*/ "exe", (char*const*) c_argv);
    jail::panic("execv failed"); // this should not be reached
}

void Runner::_setPRLimit(__rlimit_resource resource, uint64_t limit) {
    rlimit64 rlimit = {limit, limit}; // set soft and hard limit
    int rc = prlimit64(Runner::child_pid, resource, &rlimit, nullptr);
    if(rc < 0)
        jail::panic("setting prlimit failed");
}

void Runner::setPRLimits() {
    _setPRLimit(RLIMIT_AS, Runner::rlimits.total_memory_kb*1024);
    _setPRLimit(RLIMIT_STACK, Runner::rlimits.stack_kb*1024);
    _setPRLimit(RLIMIT_FSIZE, Runner::rlimits.per_file_kb*1024);
    _setPRLimit(RLIMIT_NOFILE, Runner::rlimits.open_files);
    _setPRLimit(RLIMIT_MEMLOCK, 0);
    _setPRLimit(RLIMIT_NPROC, 1);
    _setPRLimit(RLIMIT_CPU, Runner::rlimits.real_time);    
}

void Runner::forkedMonitor() {
    setIntHandler(true);
    
    // setup TimeLimit
    TimeLimit time_limit(Runner::child_pid, Runner::rlimits.instructions, Runner::rlimits.real_time, Runner::perf);
    std::thread time_limit_thread = time_limit.attach();

    setPRLimits();
    
    int wait_s;
    // initial stop from PTRACE_TRACEME
    pid_t rc = waitpid(Runner::child_pid, &wait_s, 0);
    if(rc < 0 || WIFSTOPPED(wait_s) != 1)
        jail::panic("wait failed");
    // this option creates additional event just before exit and allows to examine registers
    // change options only when stopped
    // rc = ptrace(PTRACE_SETOPTIONS, Runner::child_pid, 0, PTRACE_O_TRACEEXIT);
    // if(rc < 0)
    //     jail::panic("prace setoptions failed");
    std::cout<<"wait status exit:"<<WIFEXITED(wait_s)<<" sig:"<<WIFSIGNALED(wait_s)<<" stop:"<<WIFSTOPPED(wait_s)<<'\n';
    std::cout<<"codes s"<<WSTOPSIG(wait_s)<<" t"<<WTERMSIG(wait_s)<<'\n';
    
    rc = ptrace(PTRACE_CONT, Runner::child_pid, 0, WSTOPSIG(wait_s));
    // debug sig 6 
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
        std::cout<<"regs: rax="<<uregs.rax<<" orax="<<uregs.orig_rax<<" rip(pc)="<<uregs.rip<<'\n';
        
        std::cout<<"SENDSIG\n";
        ret = ptrace(PTRACE_CONT, Runner::child_pid, 0, WSTOPSIG(wait_s));
        if(ret < 0)
            jail::panic("ptrace_cont failed");
    }
    std::cout<<"exited with code: "<<WEXITSTATUS(wait_s)<<'\n';

    setIntHandler(false);

    time_limit_thread.detach(); // detach timelimt thread to finish on its own
    
    if(time_limit.get_killed())
        std::cout<<"killed by tlthread\n";
    if(time_limit.get_killed() == TimeLimit::REAL_TIME_EXCD /* || maxres cputime == limit */)
        std::cout<<"!! Reached real time limit\n";
    if(!time_limit.verify_insn_limit())
        std::cout<<"tle\n";
}

void Runner::setIntHandler(bool enable) {
    struct sigaction sigact;
    sigact.sa_handler = (enable ? sigint_handler : SIG_DFL);
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
}

void Runner::killChild() {
    int pid = static_child_pid; // change to map if multiple runners
    if(pid > 0 && kill(pid, 0) == 0)
        kill(pid, SIGKILL);
}

};

void sigint_handler(int signo) {
    (void) signo; // unused
    std::cout<<" Recived termination signal. Killing child process\n";
    jail::Runner::killChild();
    jail::panic("Interrupted");
}