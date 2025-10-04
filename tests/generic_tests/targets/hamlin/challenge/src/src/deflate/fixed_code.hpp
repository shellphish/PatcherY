#pragma once

#include <array>

#include "common.hpp"

#include "code.hpp"
#include "destination.hpp"

namespace deflate {
  namespace fixed_code {
    constexpr LengthArray _make_lengths() {
      LengthArray len_ary{};

      for (size_t n = 0; n <= 143; n++) {
        len_ary[n] = 8;
      }
      for (size_t n = 144; n <= 255; n++) {
        len_ary[n] = 9;
      }
      for (size_t n = 256; n <= 279; n++) {
        len_ary[n] = 7;
      }
      for (size_t n = 280; n <= 287; n++) {
        len_ary[n] = 8;
      }

      return len_ary;
    }

    constexpr LengthArray lengths = _make_lengths();

    constexpr CodeArray _make_codes(const LengthArray len_ary) {
      CodeArray code_ary{};

      uint16_t code = 0;
      std::array <uint16_t, 10> bl_count{0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      std::array <uint16_t, 10> next_code{0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

      for (byte bit_count : len_ary) {
        bl_count[bit_count] += 1;
      }

      for (byte bits = 1; bits <= 9; bits++) {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
      }

      for (uint16_t n = 0; n < CODE_COUNT; n++) {
        byte len = len_ary[n];
        if (0 != len) {
          code_ary[n] = next_code[len];
          next_code[len] += 1;
        }
      }

      return code_ary;
    }

    constexpr CodeArray codes = _make_codes(lengths);

    using BackCodeArray = std::array<uint16_t, 512>;

    constexpr BackCodeArray _invert_codes(const CodeArray codes) {
      BackCodeArray inv_ary{};

      for (uint16_t n = 0; n < CODE_COUNT; n++) {
        inv_ary[codes[n]] = n;
      }

      return inv_ary;
    }

    constexpr BackCodeArray code_to_sym = _invert_codes(codes);

    static_assert(0b10111111 == codes[143]);
    static_assert(8 == lengths[143]);
    static_assert(143 == code_to_sym[0b10111111]);

    static_assert(511 == codes[255]);
    static_assert(9 == lengths[255]);
    static_assert(255 == code_to_sym[511]);

    static_assert(0 == codes[256]);
    static_assert(7 == lengths[256]);
    static_assert(256 == code_to_sym[0]);

  }

  class FixedCode : public Code {
  public:

    virtual const Destination& get_destination(CodeBits path);
  };
}
