#include <cstdint>

#include "../assert.hpp"
#include "../hbytes.hpp"

#include "bit_vector.hpp"

using namespace deflate;

byte BitVector::read_bit() {
  uint32_t got = read_bits(1);
  assert(got <= 1);
  return (byte)got;
}

uint32_t BitVector::read_bits(byte count) {
  if (0 == count) return 0;

  assert(count <= 32);

  byte remaining_bits_this_byte = 8 - bit_cursor;

  if (count > remaining_bits_this_byte) {
    return read_bits_not_enough(count);
  }

  if (count == remaining_bits_this_byte) {
    byte got = backing[byte_cursor] >> bit_cursor;
    byte_cursor++;
    bit_cursor = 0;
    return got;
  }

  assert(count < remaining_bits_this_byte);

  byte got_too_much = backing[byte_cursor] >> bit_cursor;
  byte down_to_size = got_too_much & (( 1 << count) - 1);

  bit_cursor += count;

  return down_to_size;
}

uint32_t BitVector::read_bits_not_enough(byte count) {
  uint32_t accumulator = 0;
  byte shift = 0;

  byte remain_this_byte = 8 - bit_cursor;

  accumulator |= read_bits(remain_this_byte);
  shift += remain_this_byte;

  while (shift < count) {
    byte chonk_count = ((count - shift) > 8) ? 8 : (count - shift);
    uint32_t chonk = read_bits(chonk_count);

    accumulator |= (chonk << shift);
    shift += chonk_count;
  }

  return accumulator;
}

byte BitVector::finish_byte() {
  uint32_t got_big = read_bits(8 - bit_cursor);
  assert(got_big <= 255);

  return (byte) got_big;
}

void BitVector::inspect(std::ostream& o) const {
  o << std::hex << "BitVector byte(" << byte_cursor << ") bit("
    << (int)bit_cursor << ")" << std::endl;
}

uint16_t BitVector::read_u16() {
  uint32_t got_big = read_bits(16);
  assert(got_big <= 0xFFFF);

  return (uint16_t) got_big;
}

std::vector<byte> BitVector::read_bytes(std::size_t count) {
  assert(0 == bit_cursor);
  assert((byte_cursor + count) <= backing.size());

  std::vector<byte> ret = {};
  auto slice_start = backing.begin() + byte_cursor;
  auto slice_end = slice_start + count;
  ret.insert(ret.end(), slice_start, slice_end);

  byte_cursor += count;

  return ret;
}
