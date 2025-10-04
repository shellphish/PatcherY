#pragma once

#include <cstdint>
#include <fstream>

using dim = uint32_t;

struct Dimensions {
public:
  Dimensions(dim w, dim h) : width(w), height(h) {};

  Dimensions(const Dimensions& o) : width(o.width), height(o.height) {};

  dim width;
  dim height;
};

std::ostream& operator<<(std::ostream& os, Dimensions d);
