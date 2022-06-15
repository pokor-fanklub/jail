#pragma once

#include <stdint.h>

namespace jail {

class Perf {
    public:
        Perf() {};
        void attach();
        uint64_t readInstructions();
    private:
        int perf_fd = -1;
};

};