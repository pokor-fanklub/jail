#pragma once

#include <vector>
#include <stdint.h>
#include <seccomp.h>

namespace jail {

class Seccomp {
    public:
        enum RuleSet {
            STRICT
        };

        Seccomp(RuleSet rule_set) : rules(rule_set) {};
        void attach();
    private:
        void addGroupRules(const std::vector<int>& syscalls, uint32_t rules);

        RuleSet rules;
        scmp_filter_ctx ctx;
};

};