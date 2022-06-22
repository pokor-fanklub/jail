#pragma once

#include <string>

namespace jail {

void panic(std::string msg, bool print_errno=false) _GLIBCXX_NORETURN;

};