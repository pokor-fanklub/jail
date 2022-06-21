#include "log.h"
#include "runner.h"

#include <iostream>

namespace jail {

void panic(std::string msg) {
    std::cerr<<"panic: "<<msg<<'\n';
    Runner::killNS();
    exit(127);
}

};
