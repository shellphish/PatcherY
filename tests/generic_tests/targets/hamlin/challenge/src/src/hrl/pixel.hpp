#pragma once

#include "common.hpp"

namespace hrl {
  struct __attribute__((packed)) Pixel {
    byte r;
    byte g;
    byte b;
  };

  static_assert(sizeof(Pixel) == 3);
}
