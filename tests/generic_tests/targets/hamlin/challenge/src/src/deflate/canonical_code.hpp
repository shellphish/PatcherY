#pragma once

#include <map>

#include "bit_vector.hpp"
#include "common.hpp"

#include "code_bits.hpp"

namespace deflate {
  class CanonicalCode {
  public:
    CanonicalCode(std::vector<uint16_t> lengths);
    CanonicalCode(std::vector<byte> lengths);
    CanonicalCode() : code_bits_to_symbol({}), max_code_len(0) {};
    CanonicalCode(const CanonicalCode& other) :
      code_bits_to_symbol(other.code_bits_to_symbol),
      max_code_len(other.max_code_len) {};


    template<std::size_t array_len>
    static CanonicalCode create_from_array(std::array<uint16_t,
                                           array_len> lengths);

    template<std::size_t array_len>
    static CanonicalCode create_from_array(std::array<byte,
                                           array_len> lengths);

    uint16_t get_next_symbol(BitVector& reader);

    bool need_more_bits(CodeBits bits);
    bool is_valid_code(CodeBits bits);

    uint16_t get_symbol(CodeBits bits);

  private:
    std::map<uint16_t, uint16_t> code_bits_to_symbol;
    byte max_code_len;
  };



  template<std::size_t array_len>
  CanonicalCode
  CanonicalCode::create_from_array(std::array<uint16_t, array_len> lengths) {
    std::vector<uint16_t> dest = {};
    dest.reserve(array_len);
    for (uint16_t e : lengths) {
      dest.push_back(e);
    }

    return dest;
  }

  template<std::size_t array_len>
  CanonicalCode
  CanonicalCode::create_from_array(std::array<byte, array_len> lengths) {
    std::vector<uint16_t> dest = {};
    dest.reserve(array_len);
    for (uint16_t e : lengths) {
      dest.push_back(e);
    }

    return dest;
  }

}
