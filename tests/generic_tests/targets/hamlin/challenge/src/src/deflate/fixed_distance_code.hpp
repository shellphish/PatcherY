#pragma once

#include <array>

#include "common.hpp"
#include "code_bits.hpp"

#include "distance_code.hpp"

namespace deflate {
  namespace fixed_distance_code {
    const std::size_t DIST_CODE_COUNT = 30;

    using _distance_table_t = std::array<DistanceDestination, DIST_CODE_COUNT>;

    constexpr _distance_table_t _make_distance_table() {
      _distance_table_t tbl{};

      for (std::size_t n = 0; n < 4; n++) {
        tbl[n] = DistanceDestination(0, n+1);
      }

      for (std::size_t extra = 1; extra <= 13; extra++) {
        std::size_t base_d = 1 + (2 << extra);
        std::size_t second_d = base_d + (2 << (extra - 1));
        std::size_t base_n = 2 + extra + extra;

        tbl[base_n] = DistanceDestination(extra, base_d);
        tbl[base_n + 1] = DistanceDestination(extra,second_d);
      }

      return tbl;
    }

    constexpr _distance_table_t distance_table = _make_distance_table();

    static_assert(DistanceDestination(0, 4) == distance_table[3]);
    static_assert(DistanceDestination(7, 385) == distance_table[17]);
    static_assert(DistanceDestination(12, 8193) == distance_table[26]);

    using _code_table_t = std::array<uint16_t, DIST_CODE_COUNT>;

    constexpr _code_table_t _make_lengths() {
      _code_table_t len_ary{};

      for (size_t n = 0; n < len_ary.size(); n++) {
        len_ary[n] = 5;
      }

      return len_ary;
    }

    constexpr _code_table_t lengths = _make_lengths();

    constexpr _code_table_t _make_codes(const _code_table_t len_ary) {
      _code_table_t code_ary{};

      uint16_t code = 0;
      std::array<uint16_t, 6> bl_count{0, 0, 0, 0, 0, 0};
      std::array<uint16_t, 6> next_code{0, 0, 0, 0, 0, 0};

      for (byte bit_count : len_ary) {
        bl_count[bit_count] += 1;
      }

      for (byte bits = 1; bits <= 5; bits++) {
        code = (code + bl_count[bits - 1]) << 1;
        next_code[bits] = code;
      }

      for (uint16_t n = 0; n < DIST_CODE_COUNT; n++) {
        byte len = len_ary[n];
        if (0 != len) {
          code_ary[n] = next_code[len];
          next_code[len] += 1;
        }
      }

      return code_ary;
    }

    constexpr _code_table_t codes = _make_codes(lengths);

    constexpr _code_table_t _invert_codes(const _code_table_t codes) {
      _code_table_t inv_ary{};

      for (uint16_t n = 0; n < DIST_CODE_COUNT; n++) {
        inv_ary[codes[n]] = n;
      }

      return inv_ary;
    }

    constexpr _code_table_t code_to_sym = _invert_codes(codes);
  }

  class FixedDistanceCode : public DistanceCode {
  public:
    virtual const DistanceDestination& get_destination(CodeBits path);
  };
}
