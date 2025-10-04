#pragma once

#include <array>

#include "common.hpp"

#include "code_bits.hpp"
#include "destination.hpp"

namespace deflate {
  using LengthArray = std::array<byte, CODE_COUNT>;
  using CodeArray = std::array<uint16_t, CODE_COUNT>;

  class Code {
  public:
    virtual const Destination& get_destination(CodeBits path) = 0;

  private:

  };
}
