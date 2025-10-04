#include "canonical_code.hpp"

using namespace deflate;

CanonicalCode::CanonicalCode(std::vector<uint16_t> lengths) {
  uint16_t next_code = 0;
  max_code_len = 0;

  for (uint16_t len : lengths) {
    if (len > max_code_len) max_code_len = len;
  }

  for (uint16_t code_len = 1; code_len <= max_code_len; code_len++) {
    next_code <<= 1;
    uint16_t start_bit = 1 << code_len;
    for (std::size_t symbol = 0; symbol < lengths.size(); symbol++) {
      uint16_t symbol_len = lengths[symbol];
      if (symbol_len != code_len) continue;
      assert(next_code < start_bit);
      code_bits_to_symbol[start_bit | next_code] = symbol;
      next_code ++;
    }
  }

  assert((1 << max_code_len) == next_code);
}

CanonicalCode::CanonicalCode(std::vector<byte> lengths) {
  std::vector<uint16_t> dest = {};
  dest.reserve(lengths.size());
  for (byte e : lengths) {
    dest.push_back(e);
  }

  CanonicalCode{dest};
}

uint16_t CanonicalCode::get_next_symbol(BitVector& reader) {
  uint16_t code_bits = 1;
  for (byte len = 1; len <= max_code_len; len++) {
    code_bits = (code_bits << 1) | reader.read_bit();
    auto got = code_bits_to_symbol.find(code_bits);
    if (code_bits_to_symbol.end() != got) {
      return got->second;
    }
  }
  assert(false);
}

bool CanonicalCode::need_more_bits(CodeBits bits) {
  if (bits.len > max_code_len) return false;

  uint16_t prefix_code = bits.to_prefix_symbol();

  auto got = code_bits_to_symbol.find(prefix_code);

  if (code_bits_to_symbol.end() != got) return false;

  return true;
}

bool CanonicalCode::is_valid_code(CodeBits bits) {
  if (bits.len > max_code_len) return false;

  uint16_t prefix_code = bits.to_prefix_symbol();

  auto got = code_bits_to_symbol.find(prefix_code);

  if (code_bits_to_symbol.end() != got) return true;

  return false;
}

uint16_t CanonicalCode::get_symbol(CodeBits bits) {
  auto got = code_bits_to_symbol.find(bits.to_prefix_symbol());

  assert(code_bits_to_symbol.end() != got);

  return got->second;
}
