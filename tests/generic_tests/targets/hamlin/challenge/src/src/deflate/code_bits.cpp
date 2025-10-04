#include "code_bits.hpp"

using namespace deflate;

CodeBits CodeBits::operator+(byte bit) {
  assert(bit <= 1);
  assert(len < 255);

  return {.len = (byte)(len + 1),
          .bits = (bits << 1) | bit};
}

uint16_t CodeBits::to_prefix_symbol() {
  assert(len < 16);
  assert(bits < (1l << 16l));
  uint16_t symbol = (1 << len) + bits;
  return symbol;
}
