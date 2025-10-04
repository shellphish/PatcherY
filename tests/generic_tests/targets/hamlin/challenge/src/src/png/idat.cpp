#include "idat.hpp"

using namespace png;

Idat::Idat(Chunk c) : Chunk(c) {
  assert('IDAT' == type);
}

void Idat::inspect(std::ostream& w) {
  w << "\tIDAT bytes(" << length << ")" << std::endl;
}
