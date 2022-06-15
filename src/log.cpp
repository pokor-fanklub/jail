#include "log.h"

#include <iostream>

namespace jail {

void panic(std::string msg) {
    std::cerr<<"panic: "<<msg<<'\n';
    exit(127);
}

};
