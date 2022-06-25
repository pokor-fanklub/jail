#include "runner.h"
#include "log.h"
#include "timelimit.h"
#include "runnerjail.h"

#include <iostream>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <fcntl.h>
#include <sstream>
#include <fstream>

static pid_t static_ns_init_pid = -1;
void sigint_handler(int signo);

namespace jail {

void Runner::run() {
    // create pipe to send child pid from pid_ns_init process
    int pipe_fds[2];
    int rc = pipe2(pipe_fds, O_CLOEXEC); 
    if(rc < 0)
        jail::panic("pipe2 failed", true);

    // attach perf (only activates on exec)
    perf.attach();
    
    RunnerJail jail(pipe_fds[1], params, seccomp);
    Runner::pid_pipe_fd = pipe_fds[0];

    char* stack = (char*)malloc(1024*1024);
    int pid = clone(jail.init_clone_trampoline, stack+(1024*1024), SIGCHLD|CLONE_NEWNS|CLONE_NEWNET|CLONE_NEWIPC|CLONE_NEWPID, &jail);
    if(pid < 0)
        jail::panic("clone failed", true);

    std::cout<<"init pid: "<<pid<<'\n';
    Runner::ns_init_pid = pid;
    static_ns_init_pid = pid;

    monitorProcess();
    
    free(stack);
}

void Runner::_setPRLimit(__rlimit_resource resource, uint64_t limit) {
    rlimit64 rlimit = {limit, limit}; // set soft and hard limit
    int rc = prlimit64(Runner::jail_pid, resource, &rlimit, nullptr);
    if(rc < 0)
        jail::panic("setting prlimit failed", true);
}

void Runner::setPRLimits() {
    _setPRLimit(RLIMIT_AS, Runner::params.rlimits.total_memory_kb*1024);
    _setPRLimit(RLIMIT_STACK, Runner::params.rlimits.stack_kb*1024);
    _setPRLimit(RLIMIT_FSIZE, Runner::params.rlimits.per_file_kb*1024);
    _setPRLimit(RLIMIT_MEMLOCK, 0);
    _setPRLimit(RLIMIT_CPU, Runner::params.rlimits.real_time);    
}

void Runner::monitorProcess() {
    setIntHandler(true);

    // get jailed process pid from ns init process
    pid_t jail_pid;
    int rc  = read(Runner::pid_pipe_fd, &jail_pid, sizeof(jail_pid));
    if(rc < 0)
        jail::panic("pipe read failed", true);
    std::cout<<"received jail pid: "<<jail_pid<<'\n';
    Runner::jail_pid = jail_pid;
    
    /* Attach to jail process. Using wait is not possible, because it is not a child.
     * We can use attach as root to trace (and use wait) on random process.
     * Waiting for tracer is implemented by sigstop */
    rc = ptrace(PTRACE_SEIZE, jail_pid, 0, 0);
    if(rc < 0)
        jail::panic("ptrace attach failed", true);
    
    int wait_s; // PTRACE_ATTACH sends sigstop that needs waiting for
    rc = waitpid(Runner::jail_pid, &wait_s, 0);
    if(rc < 0 || WSTOPSIG(wait_s) != SIGSTOP)
        jail::panic("initial wait failed", true);
    
    rc = ptrace(PTRACE_SETOPTIONS, Runner::jail_pid, 0, PTRACE_O_TRACEEXIT|PTRACE_O_TRACEEXEC);
    if(rc < 0)
        jail::panic("prace setoptions failed", true);
    
    rc = ptrace(PTRACE_CONT, Runner::jail_pid, 0, 0);
    if(rc < 0)
        jail::panic("initial ptrace_cont failed", true);
    
    std::cout<<"resuming process\n";

    TimeLimit time_limit(Runner::jail_pid, Runner::params.rlimits.instructions, Runner::params.rlimits.real_time, Runner::perf);
    std::thread time_limit_thread = time_limit.attach();
    // set all limits except file limit, which is enabled on exec
    setPRLimits();

    int before_exec = 1; // start tracing for real only after exec flag
    int sigstop_count = 1; // 1st stop - wait for attach (start of init), 2nd stop - end of init
    for(;;) {
        int wait_s;
        int rc = waitpid(Runner::jail_pid, &wait_s, 0);
        if(rc < 0)
            jail::panic("wait failed");
        
        bool should_exit = WIFEXITED(wait_s) || WIFSIGNALED(wait_s);

        bool exec_flag = ((wait_s>>8) == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)));
        bool exit_flag = ((wait_s>>8) == (SIGTRAP | (PTRACE_EVENT_EXIT<<8)));

        if(should_exit) {
            // terminating status, ptrace_cont is not supported
            if(before_exec && WIFEXITED(wait_s) && WEXITSTATUS(wait_s) == 127)
                jail::panic("jail process exited before exec call (panic 127)");
            if(before_exec && WIFEXITED(wait_s))
                jail::panic("jail process exited before exec call (non-panic)");
            if(before_exec && sigstop_count <= 1 && WIFSIGNALED(wait_s))
                jail::panic("jail process setup killed by signal");
            
            if (WIFEXITED(wait_s))
                std::cout<<"exited normally with code "<<WEXITSTATUS(wait_s)<<'\n';
            else if(before_exec && sigstop_count >= 2 && WIFSIGNALED(wait_s))
                // after second SIGSTOP signal, we know that setup is done and the only instruction left is  
                // exec. It may fail by ex. receiving SIGSEGV on memory limit and this is not jail error
                std::cout<<"terminated at start of execution by signal nr."<<WTERMSIG(wait_s)<<'\n';
            else if (WIFSIGNALED(wait_s))
                std::cout<<"terminated by signal nr. "<<WTERMSIG(wait_s)<<'\n';
            
            break;
        }

        if(exec_flag && before_exec) {
            if(sigstop_count != 2)
                jail::panic("unexcepted number of stop signals before exec");

            before_exec = 0;
            std::cout<<"exec start"<<'\n';

            // setup file limit here to not interrupt setting namespace.
            _setPRLimit(RLIMIT_NOFILE, Runner::params.rlimits.open_files);
            time_limit.start_real_time_limit();
        }

        if(before_exec) {
            if(WSTOPSIG(wait_s) == SIGSTOP)
                sigstop_count++;
            
            std::cout<<"continue before exec ("<<WSTOPSIG(wait_s)<<")\n";

            // pass all singnals execept SIGSTOP, which we use to communicate
            int sig = (WSTOPSIG(wait_s) == SIGSTOP ? 0 : WSTOPSIG(wait_s));

            // thats not always the case (think bout it)
            rc = ptrace(PTRACE_CONT, Runner::jail_pid, 0, sig);
            if(rc < 0)
                jail::panic("ptrace cont failed", true);
            continue;
        }

        if(exit_flag) {
            // this is last chance to lookup registers before exit
            user_regs_struct uregs;
            rc = ptrace(PTRACE_GETREGS, Runner::jail_pid, 0, &uregs);
            if(rc < 0)
                jail::panic("ptrace_getregs failed", true);
            std::cout<<"exit regs: rax="<<uregs.rax<<" orax="<<uregs.orig_rax<<" rip(pc)="<<uregs.rip<<'\n';
            std::cout<<"mem max: "<<pidResources()<<'\n';
        }

        int fwd_signal = 0;
        if(!exec_flag && !exit_flag) {
            // pass all signals not generated by ptrace
            fwd_signal = WSTOPSIG(wait_s);
            std::cout<<"cont and forwarding signal "<<WSTOPSIG(wait_s)<<'\n';
        } else {
            // this signal be SIGTRAP generated by ptrace
            std::cout<<"cont and ignoring signal\n";
        }
        rc = ptrace(PTRACE_CONT, Runner::jail_pid, 0, fwd_signal);
        if(rc < 0)
            jail::panic("ptrace cont failed", true);
    }
    
    killNS(); // end init process
    setIntHandler(false);
    time_limit_thread.detach(); // detach timelimt thread to finish on its own

    if(time_limit.get_killed())
        std::cout<<"Process was killed by timelimit thread: ";
    if(time_limit.get_killed() == TimeLimit::REAL_TIME_EXCD)
        std::cout<<"RLE (real time)\n";
    if(!time_limit.verify_insn_limit())
        std::cout<<"TLE (intstructions)\n";
    std::cout<<perf.readInstructions()<<" instructions"<<'\n';
}

int Runner::pidResources() {
    // get resources usage from procfs. More accurate and allows using pid
    std::stringstream proc_name;
    proc_name<<"/proc/"<<Runner::jail_pid<<"/status";
    std::ifstream proc_file(proc_name.str());
    std::string w, res = "";
    while (proc_file >> w) {
        if(w == "VmPeak:") {
            proc_file>>res;
            break;
        }
    }

    int mempeak = atoi(res.c_str());
    if(!mempeak && res != "0")
        jail::panic("failed to read from procfs");

    proc_file.close();
    return mempeak;
}

void Runner::killNS() {
    // by killing namespace init process, whole namespace is killed 
    int pid = static_ns_init_pid;
    if(pid > 0 && kill(pid, 0) == 0)
        kill(pid, SIGKILL);
}

void Runner::setIntHandler(bool enable) {
    struct sigaction sigact;
    sigact.sa_handler = (enable ? sigint_handler : SIG_DFL);
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);
}

};

void sigint_handler(int signo) {
    (void) signo; // unused
    std::cout<<" Recived termination signal. Killing child process\n";
    jail::Runner::killNS();
    jail::panic("Interrupted");
}
