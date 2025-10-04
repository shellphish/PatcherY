#include <arpa/inet.h>

#include "ihdr.hpp"

using namespace png;

Ihdr::Ihdr(Chunk c) : Chunk(c) {
  assert(13 == length);
  assert('IHDR' == type);
  assert(sizeof(Pack) == data.size());

  Pack* pd = (Pack*)(void*) data.data();

  cols = ntohl(pd->cols);
  rows = ntohl(pd->rows);
  bit_depth = pd->bit_depth;
  color_type = (ColorType) pd->color_type;
  compression = pd->compression;
  filter = pd->filter;
  interlace = pd->interlace;

}

void Ihdr::inspect(std::ostream& w) {
  Chunk::inspect(w);
  w << "\tIHDR dimensions(" << dimensions() << ") bit depth(" <<
    (int)bit_depth << ") color_type(" << color_type << ") compression(" <<
    (int)compression << ") filter(" << (int)filter <<
    ") interlace(" << (int)interlace <<
    ")" << std::endl;
}

Dimensions Ihdr::dimensions() {
  return Dimensions{cols, rows};
}
