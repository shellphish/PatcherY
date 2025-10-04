#pragma once

#include <cstdint>
#include <ostream>

#include "../hbytes.hpp"

#include "bit_vector.hpp"

namespace deflate {
  class ZlibHeader {
  public:
    ZlibHeader(BitVector& bv);

    byte compression_method;
    byte compression_info;

    byte preset_dictionary;
    byte compression_level;

    void validate_png() const;

    uint32_t window_size() const;

    void inspect(std::ostream& w) const;
  };
}
