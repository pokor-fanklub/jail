#include "perf.h"
#include "runner.h"

#include <iostream>
#include <string>

void printHelp(std::string basename) {
    std::string help = \
    "Usage: " + basename + " [parameters] -- [run command]\n";
    std::cout<<help;
}

int main(int argc, char* argv[]) {
    jail::Perf perf;
    printHelp(argv[0]);
    perf.attach();
    jail::Seccomp scmp(jail::Seccomp::STRICT);
    limits default_limits;
    jail::Runner runner("/home/piotro/wa-jail/test/pid.test", {"arg"}, default_limits, perf, scmp);
    runner.run();
    std::cout<<perf.readInstructions()<<'\n';
}
