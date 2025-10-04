#include "plte.hpp"

using namespace png;

Plte::Plte(Chunk c) : Chunk(c) {
  assert(0 == (length % 3));
  assert('PLTE' == type);

  entry_count = length / 3;

  assert(entry_count >= 1);
  assert(entry_count <= 256);

  palette.resize(entry_count, {0, 0, 0});

  for (std::size_t n = 0; n < entry_count; n++) {
    std::size_t offset = n * 3;

    palette[n] = {
                  data[offset + 0],
                  data[offset + 1],
                  data[offset + 2]
    };
  }
}

Rgba Plte::operator[](byte pal_idx) const {
  assert(pal_idx < entry_count);

  return palette[pal_idx];
}

void Plte::inspect(std::ostream& w) {
  Chunk::inspect(w);
  w << "\tPLTE entry_count(" << entry_count << ") entries(" << std::endl;
  for (std::size_t n = 0; n < entry_count; n++) {
    w << "\t\t" << n << ": {";
    w << (int)palette[n].r << " "
      << (int)palette[n].g << " "
      << (int)palette[n].b << "}" << std::endl;
  }
}
