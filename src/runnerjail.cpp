#include "runnerjail.h"
#include "log.h"
#include "ns.h"

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
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
    ns.addMountPath({params.exec_path, "/exe", true});
    setupFdsNs(ns);
    for(auto ent: params.ns_ent)
        ns.addMountPath(ent);
    ns.isolate();
    
    // drop privileges
    setresgid(params.gid, params.gid, params.gid);
    setresuid(params.uid, params.uid, params.uid);

    seccomp.attach();

    // construct arguments
    const char* c_argv[params.exec_args.size()+2];
    c_argv[0] = params.exec_path.c_str();
    for(size_t i = 0; i < params.exec_args.size(); i++)
        c_argv[i+1] = params.exec_args[i].c_str();
    c_argv[2] = nullptr;

    // setup stdin/stout/sterr
    changeFds();
    
    raise(SIGSTOP); // signal tracer that setup is done and all signals from now belong to process

    execv("/exe", (char * const *) c_argv);
    jail::panic("jail: execv failed");
}

void RunnerJail::setupFdsNs(Namespaces& ns) {
    if(params.in_file != "") {
        ns.addMountPath({params.in_file, "/in", true});
    }
    if(params.out_file != "") {
        ns.addMountPath({params.out_file, "/out", false});
    }
    if(params.err_file != "") {
        ns.addMountPath({params.err_file, "/err", false});
    } else {
        ns.addMountPath({"/dev/null", "/err", false});
    }
}

void RunnerJail::changeFds() {
    if(params.in_file != "") {
        close(0);
        int fd = open("/in", O_RDONLY);
        if(fd != 0)
            jail::panic("failed to open /in", true);
    }
    if(params.out_file != "") {
        close(1);
        int fd = open("/out", O_TRUNC|O_WRONLY);
        if(fd != 1)
            jail::panic("failed to open /out", true);
    }
    close(2);
    int fd = open("/err", O_TRUNC|O_WRONLY);
    if(fd != 2)
        jail::panic("failed to open /out", true);
    
    int rc = close_range(3, UINT32_MAX, 0);
    if(rc < 0)
        jail::panic("close range failed", true);
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
