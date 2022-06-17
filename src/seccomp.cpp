#include "seccomp.h"

#include "log.h"

#include <utility>
#include <seccomp.h>
#include <syscall.h>

namespace jail {

void Seccomp::addGroupRules(const std::vector<int>& syscalls, uint32_t rule) {
    for (int sys : syscalls) {
        seccomp_rule_add(Seccomp::ctx, rule, sys, 0);
    }
}

void Seccomp::attach() {
    Seccomp::ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
    addGroupRules({
            SYS_execve,
            SYS_exit,
            SYS_mmap,
            SYS_munmap,
            SYS_brk,
            SYS_arch_prctl,
            SYS_access,
            SYS_openat,
            SYS_newfstatat,
            SYS_pread64,
            SYS_set_tid_address,
            SYS_set_robust_list,
            SYS_rseq,
            SYS_mprotect,
            SYS_read,
            SYS_write,
            SYS_open,
            SYS_close,
            SYS_uname,
            SYS_prlimit64,
            SYS_readlink,
            SYS_getrandom,
            SYS_exit_group,
            SYS_rt_sigprocmask,
            SYS_gettid,
            SYS_getpid,
            SYS_tgkill,
            SYS_rt_sigaction,
            SYS_futex
        },
        SCMP_ACT_ALLOW);

    int rc = seccomp_load(ctx);
    if(rc < 0)
        jail::panic("seccomp_load failed");
}
    
};
