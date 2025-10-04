#include "chunk.hpp"

using namespace png;

Chunk::Chunk(std::istream& r) {
  uint32_t len_n;
  r.read((char*)(void*)&len_n, sizeof(len_n));
  length = ntoh(len_n);

  uint32_t type_n;
  r.read((char*)(void*)&type_n, sizeof(type_n));
  type = ntoh(type_n);

  data.resize(length);
  if (0 != length) {
    r.read((char*)(void*)data.data(), length);
  }

  uint32_t crc_n;
  r.read((char*)(void*)&crc_n, sizeof(crc_n));
  crc = ntoh(crc_n);

  crc32::crc_t calc_crc = crc32::calculate_begin((char*)(void*)&type_n,
                                                 sizeof(type_n));
  calc_crc = crc32::calculate_inter(calc_crc, (char*)data.data(), data.size());
  calc_crc = crc32::calculate_final(calc_crc);

  lll("len %x type %c%c%c%c (%x)", length,
      0xFF & (type >> 24),
      0xFF & (type >> 16),
      0xFF & (type >> 8),
      0xFF & (type),
      type);
  lll("crc at got %x expected %x", calc_crc, crc);

  // assert(calc_crc == crc);
}

void Chunk::inspect(std::ostream& w) {
  w << "Chunk length(" << length << ") type(" << type << ") crc(" << crc << ") "
    << std::endl;
}

void Chunk::assert_crc() {

}


std::string Chunk::type_string() {
  std::string dest = "1234";
  sprintf(dest.data(), "%c%c%c%c",
          0xFF & (type >> 24),
          0xFF & (type >> 16),
          0xFF & (type >> 8),
          0xFF & (type >> 0));

  return dest;
}
