#include "iend.hpp"

using namespace png;

Iend::Iend(Chunk c) : Chunk(c) {
  assert('IEND' == type);
  assert(0 == length);
}
