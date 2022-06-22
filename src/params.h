#pragma once

#include <vector>

#include "limits.h"
#include "seccomp.h"
#include "ns.h"

struct Params {
    bool verbose = false;
    limits rlimits;
    std::string in_file = "", out_file = "", err_file = "", jail_dir = "./jail/";
    jail::Seccomp::RuleSet sec_rs = jail::Seccomp::RuleSet::STRICT;
    uint uid = 65534, gid = 65534;
    std::vector <jail::Namespaces::mount_entry> ns_ent;
    std::string exec_path = "";
    std::vector <std::string> exec_args;
};
