#pragma once

#include <array>
#include <vector>

#include "common.hpp"

#include "zlib_header.hpp"

namespace deflate {
  constexpr uint32_t MAX_HISTORY = 32768;

  class History {
  public:
    virtual void append(byte b) = 0;
    virtual std::vector<byte> copy(uint32_t dist, uint16_t count) = 0;

    virtual ~History() {};
  };
}
