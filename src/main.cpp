#include "runner.h"
#include "params.h"
#include "log.h"

#include <iostream>
#include <string>
#include <getopt.h>

void printHelp(std::string basename) {
    std::string help = \
    "Usage: " + basename + " [parameters] -- [run command]\n" +
    "Parametes:\n" +
    "-v - verbose output\n" +
    "-t <instructions> - instruction limit (default: 2e9)\n" +
    "--tr <seconds> - real time limit (limit if program hangs, default: 10s)\n" +
    "-m <memory kB> - limit on virtual memory (data+stack+heap+exec)\n" +
    "--ms <memory kB> - separete limit of stack memory (default: disabled)\n" +
    "--mf <memory kB> - limit of single file size (default: 100kB)\n" +
    "--of <number> - limit of open files (default: 3 - stdin+out+err)\n" +
    "-i <path> - stdin file or fifo (default: stdin)\n" +
    "-o <path> - stdout file or fifo (default: stdout)\n" + 
    "--oe <path> - stderr file or fifo (default: ignore)\n" +
    "-s <num> - select syscall rule set: 0-STRICT(default), 1-DISABLED)\n" +
    "--user <uid>:<gid> - user and group on which jail will be executed (default: nouser:nogroup)\n" + 
    "--jaildir <path> - directory used as jail mount point (not written) (default: ./jail/)\n" +
    "--mount <src path>:<dest path in jail>:<rw|ro> - mount additional files to jail\n" +
    "--help - print help\n";
    std::cout<<help;
    exit(0);
}

Params parseArgs(int argc, char* argv[]);

int main(int argc, char* argv[]) {
    Params par = parseArgs(argc, argv);
    
    jail::Runner runner(par);
    runner.run();
}

static bool arg_error = false;

long long atoll_wc(const char* str) {
    long long res = atoll(str);
    if(res == 0 && std::string(str) != "0") {
        std::cerr<<"invalid number argument\n";
        arg_error = true;
    }
    return res;
}

Params parseArgs(int argc, char* argv[]) {
    static option long_options[] = {
        {"tr", required_argument, 0, 0},
        {"ms", required_argument, 0, 0},
        {"mf", required_argument, 0, 0},
        {"of", required_argument, 0, 0},
        {"oe", required_argument, 0, 0},
        {"user", required_argument, 0, 0},
        {"jaildir", required_argument, 0, 0},
        {"mount", required_argument, 0, 0},
        {"help", no_argument, 0, 0},
        {0, 0, 0, 0}
    };
    const char* short_opts = "vt:m:i:o:s:";

    Params p;

    int opt, long_idx;
    while((opt = getopt_long(argc, argv, short_opts, long_options, &long_idx)) != -1) {
        switch (opt) {
            case 'v':
                p.verbose = true;
                break;
            case 't':
                p.rlimits.instructions = atoll_wc(optarg);
                break;
            case 'm':
                p.rlimits.total_memory_kb = atoll_wc(optarg);
                break;
            case 'i':
                p.in_file = std::string(optarg);
                break;
            case 'o':
                p.out_file = std::string(optarg);
                break;
            case 's': {
                int opt_i = (int) atoll_wc(optarg);
                switch (opt_i) {
                    case 0:
                        p.sec_rs = jail::Seccomp::RuleSet::STRICT;
                        break;
                    case 1:
                        p.sec_rs = jail::Seccomp::RuleSet::DISABLED;
                        break;
                    default:
                        std::cerr<<"Invalid -s argument\n";
                        arg_error = true;
                        break;
                }
                break;
            }
            case 0: {
                switch (long_idx) {
                    case 0:
                        p.rlimits.real_time = atoll_wc(optarg);
                        break;
                    case 1:
                        p.rlimits.stack_kb = atoll_wc(optarg);
                        break;
                    case 2:
                        p.rlimits.per_file_kb = atoll_wc(optarg);
                        break;
                    case 3:
                        p.rlimits.open_files = atoll_wc(optarg);
                        break;
                    case 4:
                        p.err_file = std::string(optarg);
                        break;
                    case 5: {
                        std::string arg_s = optarg;
                        int sep = arg_s.find(':');
                        if(sep == -1) {
                            std::cerr<<"invalid --user entry\n";
                            arg_error = true;
                            break;
                        }
                        p.uid = atoll_wc(arg_s.substr(0, sep).c_str());
                        p.gid = atoll_wc(arg_s.substr(sep+1).c_str());
                        break;
                    } 
                    case 6:
                        p.jail_dir = std::string(optarg);
                        break;
                    case 7: {
                        std::string arg_s = optarg;
                        int sep_f = arg_s.find(':', 0);
                        int sep_s = arg_s.find(':', sep_f+1);
                        if(sep_f == -1 || sep_s == -1) {
                            std::cerr<<"invalid --mount entry\n";
                            arg_error = true;
                            break;
                        }
                        jail::Namespaces::mount_entry ent;
                        ent.in_path = arg_s.substr(0, sep_f);
                        ent.out_path = arg_s.substr(sep_f+1, (sep_s-sep_f-1));
                        ent.read_only = (arg_s.substr(sep_s+1) == "rw" ? 0 : 1);
                        p.ns_ent.push_back(ent);
                        break;
                    } 
                    case 8:
                        printHelp(argv[0]);
                        break;
                    default:
                        jail::panic("error parsing options");
                        break;
                }
                break;
            }
            case '?':
                arg_error = true;
                break;
            default:
                jail::panic("error parsing options");
        }
    }

    bool skip_opts = true;
    for(int i=0; i<argc; i++) {
        if(skip_opts) {
            if(std::string(argv[i]) == "--") {
                skip_opts = false;
            }
            continue;
        }
        if(p.exec_path == "")
            p.exec_path = std::string(argv[i]);
        else
            p.exec_args.push_back(argv[i]);
    }

    if(skip_opts) {
        std::cerr<<"missing -- before command\n";
        arg_error = true;
    }

    if(arg_error)
        jail::panic("error in arguments");
    
    return p;
}