#include "colortype.hpp"

using namespace png;

std::ostream& operator<<(std::ostream& os, ColorType c) {
  switch (c) {
  case greyscale:
    os << "greyscale";
    break;
  case rgb:
    os << "rgb";
    break;
  case palette:
    os << "palette";
    break;
  case greyscale_alpha:
    os << "greyscale_alpha";
    break;
  case rgba:
    os << rgba;
    break;
  default:
    os << "unknown colortype " << (uint8_t)c;
    break;
  }

  return os;
}
