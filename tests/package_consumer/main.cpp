#include "stealthlib/stealth.hpp"

#include <cstring>

int main() {
    auto secret = S("package-consumer");
    return std::strcmp(secret.c_str(), "package-consumer") == 0 ? 0 : 1;
}
