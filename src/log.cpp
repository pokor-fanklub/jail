#include "log.h"
#include "runner.h"

#include <iostream>

namespace jail {

void panic(std::string msg) {
    std::cerr<<"panic: "<<msg<<'\n';
    Runner::killChild();
    exit(127);
}

};
