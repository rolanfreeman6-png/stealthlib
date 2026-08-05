#include "stealthlib/stealth.hpp"

#include <cstring>

int main() {
    auto secret = S("subproject-consumer");
    return std::strcmp(secret.c_str(), "subproject-consumer") == 0 ? 0 : 1;
}
