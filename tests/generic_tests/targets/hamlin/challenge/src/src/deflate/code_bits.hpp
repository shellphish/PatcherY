#pragma once

#include "common.hpp"

namespace deflate {
  struct CodeBits {
    byte len = 0;
    uint32_t bits = 0;

    CodeBits operator+(byte bit);

    uint16_t to_prefix_symbol();
  };
}
