#include <array>

#include "hbytes.hpp"

#include "rgba.hpp"

std::array<byte, 4> Rgba::to_pxarray() {
  return {r, g, b, a};
}

bool operator==(const Rgba& l, const Rgba& r) {
  if (l.r != r.r) return false;
  if (l.g != r.g) return false;
  if (l.b != r.b) return false;
  if (l.a != r.a) return false;

  return true;
}
