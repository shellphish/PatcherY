#include "../assert.hpp"

#include "zlib_header.hpp"

using namespace deflate;

ZlibHeader::ZlibHeader(BitVector& bv) {
  compression_method = (byte)bv.read_bits(4);
  compression_info = (byte)bv.read_bits(4);

  byte cmf_byte = (compression_info << 4) | (compression_method);

  byte cmf_ck = (byte)bv.read_bits(5);

  preset_dictionary = (byte)bv.read_bits(1);
  compression_level = (byte)bv.read_bits(2);

  byte flag_byte =
    (compression_level << 6) |
    (preset_dictionary << 5) |
    (cmf_ck);

  uint16_t flag_check = (cmf_byte << 8) | flag_byte;

  assert((flag_check % 31) == 0);
}

uint32_t ZlibHeader::window_size() const {
  return 1 << (8 + compression_info);
}

void ZlibHeader::validate_png() const {
  assert(8 == compression_method);
  assert(7 >= compression_info);

  assert(0 == preset_dictionary);
}

void ZlibHeader::inspect(std::ostream& w) const {
  w << std::hex
    << "method(" << (int)compression_method
    << ") info(" << (int)compression_info
    << ") preset_dict(" << (bool)preset_dictionary
    << ") level(" << (int)compression_level
    << ")" << std::endl;
}
