#include "log.h"
#include "runner.h"
#include "output.h"

#include <iostream>
#include <string.h>

namespace jail {

void panic(std::string msg, bool print_errno) {
    std::cerr<<"panic: "<<msg;
    if(print_errno)
        std::cerr<<" ("<<strerror(errno)<<")";
    std::cerr<<'\n';
    Runner::killNS();
    Output::print_sys_err();
    exit(127);
}

};
