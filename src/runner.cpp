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
#include <fcntl.h>
#include <sstream>
#include <fstream>

static pid_t static_ns_init_pid = -1;
void sigint_handler(int signo);
extern char* our_stack;

namespace jail {

int Runner::clone_trampoline(void* arg) {
    reinterpret_cast<jail::Runner*>(arg)->nsInitProcess();
    jail::panic("returned to trampoline");
}

void Runner::run() {
    int rc = pipe2(monitor_init_pipe, O_CLOEXEC); // create pipe to send child pid from pid_ns_init process
    if(rc < 0)
        jail::panic("pipe2 failed");

    char* stack = (char*)malloc(1024*1024);
    int pid = clone(clone_trampoline, stack+(1024*1024), SIGCHLD|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWPID, this);
    if(pid < 0)
        jail::panic("clone failed");

    std::cout<<"pid"<<pid<<'\n';
    Runner::ns_init_pid = pid;
    static_ns_init_pid = pid;
    monitorProcess();
    free(stack);
}

void Runner::nsInitProcess() {
    /* This process is necessary, because it becomes init process of new PID namespace. 
     * Sending signals withot explicit handlers (other than SIGKILL from parent) 
     * is not supported, but we want to handle signals (such as SIGABORT) from
     * jailed process correctly. We can't forward signals from parent and init process can't
     *  send signals to itself. We want jailed process to run under init and now normal signaling works.
     */ 

    pid_t jpid = fork();
    if(jpid < 0)
        jail::panic("init->jail fork failed");
    if(jpid == 0) {
        jailProcess();
        jail::panic("jail process returned");
    }
    
    // send child pid to parent
    assert(!close(monitor_init_pipe[0]));
    int rc = write(monitor_init_pipe[1], &jpid, sizeof(jpid));
    if(rc < 0) {
        close(monitor_init_pipe[1]); // this may fail, try to unblock parent
        jail::panic("write to pipe failed");
    }
    assert(!close(monitor_init_pipe[1]));
    
    // this process needs to stay alive as a namespace init process
    // we can't wait for child because another process is tracing it, we relay on monitor 
    // to sigkill this process (and namespace) when jailed process exits
    for(;;)
        pause();
}

void Runner::jailProcess() {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    
    raise(SIGSTOP); // this stops until PTRACE attaches and recieves this signal

    const char* c_argv[Runner::exec_args.size()+2];
    c_argv[0] = Runner::exec_name.c_str();
    for(size_t i = 0; i < Runner::exec_args.size(); i++)
        c_argv[i+1] = Runner::exec_args[i].c_str();
    c_argv[2] = nullptr;
   
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
    int rc = prlimit64(Runner::jail_pid, resource, &rlimit, nullptr);
    if(rc < 0)
        jail::panic("setting prlimit failed");
}

void Runner::setPRLimits() {
    _setPRLimit(RLIMIT_AS, Runner::rlimits.total_memory_kb*1024);
    _setPRLimit(RLIMIT_STACK, Runner::rlimits.stack_kb*1024);
    _setPRLimit(RLIMIT_FSIZE, Runner::rlimits.per_file_kb*1024);
    _setPRLimit(RLIMIT_NOFILE, Runner::rlimits.open_files);
    _setPRLimit(RLIMIT_MEMLOCK, 0);
    _setPRLimit(RLIMIT_CPU, Runner::rlimits.real_time);    
}

int Runner::getRealJailPid() {
    std::stringstream proc_path;
    proc_path<<"/proc/"<<Runner::ns_init_pid<<"/task/"<<Runner::ns_init_pid<<"/children";
    std::ifstream proc_file(proc_path.str());
    int jpid;
    if(!(proc_file>>jpid))
        jail::panic("eof while reading proc file");
    if(proc_file>>jpid) {
        jail::panic("proc file too long");
    }

    proc_file.close();
    return jpid;
}

void Runner::monitorProcess() {
    setIntHandler(true);

    assert(!close(monitor_init_pipe[1]));
    pid_t jpid;
    int r = read(monitor_init_pipe[0], &jpid, sizeof(jpid));
    if(r<0)
        jail::panic("pipe read failed");
   
    std::cout<<"received pids jail: "<<jpid<<" from init:"<<Runner::ns_init_pid<<'\n';
    Runner::jail_pid = getRealJailPid();
    std::cout<<"resolved jail pid: "<<jail_pid<<'\n';

    // FIXME: CHILD MAY DIE BEFORE THERE, print some debug in 
    // setup TimeLimit
    TimeLimit time_limit(Runner::jail_pid, Runner::rlimits.instructions, Runner::rlimits.real_time, Runner::perf);
    std::thread time_limit_thread = time_limit.attach();

    setPRLimits();
    int rrc = ptrace(PTRACE_ATTACH, jail_pid);
    if(rrc < 0)
        printf("%m panic atttach failed %d\n", getuid());
    int wait_s;

    // initial stop from PTRACE_TRACEME
    pid_t rc = waitpid(Runner::jail_pid, &wait_s, 0);

    if(rc < 0 || WIFSTOPPED(wait_s) != 1)
        jail::panic("initial wait failed");
    // this option creates additional event just before exit and allows to examine registers
    // change options only when stopped
    rc = ptrace(PTRACE_SETOPTIONS, Runner::jail_pid, 0, PTRACE_O_TRACEEXIT|PTRACE_O_TRACEEXEC);
    if(rc < 0)
        jail::panic("prace setoptions failed");
    rc = ptrace(PTRACE_CONT, Runner::jail_pid, 0, 0);

    // debug sig 6 
    if(rc < 0)
        jail::panic("initial ptrace_cont failed");
    std::cout<<"resuming after initial stop\n";

    int wait_ignore = 1;

    for(;;) {
        pid_t rc = waitpid(Runner::jail_pid, &wait_s, 0);
        if(rc < 0)
            jail::panic("wait failed");
        
        if(wait_ignore) {
            if((wait_s>>8) == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)))
                wait_ignore = 0;
        }

        std::cout<<"wait status exit:"<<WIFEXITED(wait_s)<<" sig:"<<WIFSIGNALED(wait_s)<<" stop:"<<WIFSTOPPED(wait_s)<<'\n';
        std::cout<<"codes s"<<WSTOPSIG(wait_s)<<" t"<<WTERMSIG(wait_s)<<" trace_exit"<<((wait_s>>8) == (SIGTRAP | (PTRACE_EVENT_EXIT<<8)))<<" exec"<<((wait_s>>8) == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)))<<'\n';

        if(!wait_ignore) {
            rusage ru;
            getrusage(RUSAGE_CHILDREN, &ru);
            std::cout<<"rusage"<<ru.ru_maxrss*1024<<" realruntime"<<ru.ru_utime.tv_sec+ru.ru_stime.tv_sec<<"\n";
        }
        // both of those are terminating signals and don't allow PTRACE_CONT
        if(WIFEXITED(wait_s) || WIFSIGNALED(wait_s)) {
            if(WIFSIGNALED(wait_s))
                std::cout<<"killed by singal!\n";
            else
                std::cout<<"exited normally\n";
            break;
        }

        if(!wait_ignore) {
            // std::stringstream proc_path;
            // proc_path<<"/proc/"<<Runner::jail_pid<<"/status";
            // std::ifstream proc_file(proc_path.str());
            // std::string line;
            // while(proc_file>>line) {
            //     std::cout<<line<<'\n';
            // }
            // proc_file.close();

            user_regs_struct uregs;
            long ret = ptrace(PTRACE_GETREGS, Runner::jail_pid, 0, &uregs); // this is not available when exit status is set
            if(ret < 0)
                jail::panic("ptrace_getregs failed");
            std::cout<<"regs: rax="<<uregs.rax<<" orax="<<uregs.orig_rax<<" rip(pc)="<<uregs.rip<<'\n';
        }

        int sigres = (WSTOPSIG(wait_s) == SIGTRAP || WSTOPSIG(wait_s) == SIGSTOP ? 0 : WSTOPSIG(wait_s));
        if(sigres > 0)
            std::cout<<"SENDSIG\n";
        int ret = ptrace(PTRACE_CONT, Runner::jail_pid, 0, sigres);
        if(ret < 0)
            jail::panic("ptrace_cont failed");
        std::cout<<"----------------------\n";
    }
    std::cout<<"exited with code: "<<WEXITSTATUS(wait_s)<<'\n';

    rusage ru;
    getrusage(RUSAGE_CHILDREN, &ru);
    std::cout<<"rusage"<<ru.ru_maxrss*1024<<" realruntime"<<ru.ru_utime.tv_sec+ru.ru_stime.tv_sec<<"\n";
    

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

void Runner::killNS() {
    int pid = static_ns_init_pid; // by killing namespace init process, all namespace is killed
    if(pid > 0 && kill(pid, 0) == 0)
        kill(pid, SIGKILL);
}

};

void sigint_handler(int signo) {
    (void) signo; // unused
    std::cout<<" Recived termination signal. Killing child process\n";
    jail::Runner::killNS();
    jail::panic("Interrupted");
}