#include "perf.h"

#include "log.h"

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <errno.h>

namespace jail {

/**
 * Setup perf on current process to start counting
 * after using execv syscall (also on child process
 * without counting parent)
 */
void Perf::attach() {
    perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(perf_event_attr);
    attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    attr.disabled = 1;
    attr.inherit = 1;
    attr.enable_on_exec = 1;
    attr.exclude_user = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    int fd = syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
    if(fd < 0)
        jail::panic("perf_event_open failed");
    Perf::perf_fd = fd;
}
uint64_t Perf::readInstructions() {
    uint64_t instructions;
    int rc = read(Perf::perf_fd, &instructions, sizeof(instructions));
    if(rc != sizeof(instructions))
        jail::panic("read from perf_fd failed");
    
    return instructions;
}

};
