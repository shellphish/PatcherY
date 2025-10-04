#include "dimensions.hpp"

std::ostream& operator<<(std::ostream& os, Dimensions d) {
  os << d.width << "x" << d.height;
  return os;
}
