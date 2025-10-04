#pragma once

#include "common.hpp"

namespace hrl {
  struct __attribute__((packed)) Run {
    byte sigil;
    byte length;
    byte r;
    byte g;
    byte b;
  };

  static_assert(sizeof(Run) == 5);
}
