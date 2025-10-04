#pragma once

#include <array>

#include "hbytes.hpp"

class Rgba {
public:
  Rgba(byte red, byte green, byte blue) : r(red), g(green), b(blue) {};
  Rgba(byte red, byte green, byte blue, byte alpha) :
    r(red), g(green), b(blue), a(alpha) {};

  Rgba(std::array<byte, 3> px) : r(px[0]), g(px[1]), b(px[2]) {};
  Rgba(std::array<byte, 4> px) : r(px[0]), g(px[1]), b(px[2]), a(px[3]) {};

  std::array<byte, 4> to_pxarray();

  byte r;
  byte g;
  byte b;
  byte a = 255;
};

bool operator==(const Rgba& l, const Rgba& r);
