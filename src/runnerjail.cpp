#include "runnerjail.h"
#include "log.h"
#include "ns.h"

#include <unistd.h>
#include <signal.h>
#include <fstream>
#include <iostream>

namespace jail {

int RunnerJail::init_clone_trampoline(void* arg) {
    // function to use clone syscall on static pointers
    static_cast<RunnerJail*>(arg)->init_main();
    jail::panic("trampoline: init returned");
}

void RunnerJail::init_main() {
    /* This becomes a init (pid 1) process of new pid_namespace.
     * We need to fork it because init process cannot receive any
     * unhanled signals, even from itself  (except of sigkill from 
     * parent which kills the whole namespace). We need signal handling 
     * for ptrace. */

    pid_t jail_pid = fork();
    if(jail_pid < 0)
        jail::panic("init: fork failed");
    
    if(jail_pid == 0) {
        jail_main();
        jail::panic("init: jail returned");
    }
    
    int real_jail_pid = getRealChildPid();
    // FIXME: Use soft panic and write to pipe -1 if we failed 

    // send real child pid to parent
    int rc = write(pid_pipe, &real_jail_pid, sizeof(real_jail_pid));
    if (rc < 0)
        jail::panic("init: write to pipe failed");
    rc = close(pid_pipe);
    if (rc < 0)
        jail::panic("init: pipe close failed");

    for(;;)
        pause(); // we can't wait for child, because tracer does it;
                 // execpt kill from parent at jailed proces finish
}

void RunnerJail::jail_main() {
    /* hax: We can't use ptrace_traceme, becasue parent is
     * not a tracer. Raise stop signal to stop process until
     * someone attaches with ptrace_attach and handles the signal */
    raise(SIGSTOP);
    
    // prepare jail environment
    Namespaces ns;
    ns.addMountPath({exec_name, "/exe", true});
    ns.isolate();
    
    // drop privileges
    setresgid(gid, gid, gid);
    setresuid(uid, uid, uid);

    seccomp.attach();

    // construct arguments
    const char* c_argv[exec_args.size()+2];
    c_argv[0] = exec_name.c_str();
    for(size_t i = 0; i < exec_args.size(); i++)
        c_argv[i+1] = exec_args[i].c_str();
    c_argv[2] = nullptr;

    execv("/exe", (char * const *) c_argv);
    jail::panic("jail: execv failed");
}

int RunnerJail::getRealChildPid() {
    // we can recover real (not ns) child pid from procfs
    std::ifstream proc_file("/proc/thread-self/children");
    int pid;
    
    if(!(proc_file>>pid)) { 
        printf("%m");
        jail::panic("init: failed to read procfs");
    }
    proc_file.close();
    return pid;
}

};