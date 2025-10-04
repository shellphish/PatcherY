#pragma once

#include <ostream>
#include <vector>

#include "../hbytes.hpp"

namespace deflate {
  class BitVector {
  public:
    BitVector(const std::vector<byte> v) :
      backing(v), byte_cursor(0), bit_cursor(0) {};

    BitVector(const BitVector&) = delete; // don't copy

    byte read_bit();
    uint32_t read_bits(byte count);

    byte finish_byte();

    uint16_t read_u16();
    std::vector<byte> read_bytes(std::size_t count);

    void inspect(std::ostream& o) const;

  private:
    const std::vector<byte> backing;
    std::size_t byte_cursor;
    byte bit_cursor;

    uint32_t read_bits_not_enough(byte count);
  };

}
