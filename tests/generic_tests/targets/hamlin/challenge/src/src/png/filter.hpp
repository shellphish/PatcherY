#pragma once

#include <vector>

#include "common.hpp"

namespace png {
  enum class FilterType : byte {
                                none = 0,
                                sub = 1,
                                up = 2,
                                average = 3,
                                paeth = 4,
                                _unknown = 255,
  };

  namespace filter {
    using PixelVec = std::vector<Rgba>;
    using ByteVec = std::vector<byte>;

    class Base {
    public:
      virtual ByteVec decode_first_row(ByteVec row,
                                        uint32_t cols,
                                        byte bytes_per_pixel) const = 0;
      virtual ByteVec decode_row(ByteVec row,
                                  uint32_t cols,
                                  byte bytes_per_pixel,
                                  ByteVec prev_row) const = 0;
    };

    class None : public Base {
    public:
      virtual ByteVec decode_first_row(ByteVec row,
                                        uint32_t cols,
                                        byte bytes_per_pixel) const override;
      virtual ByteVec decode_row(ByteVec row,
                                  uint32_t cols,
                                  byte bytes_per_pixel,
                                  ByteVec prev_row) const override;
    };

    class Sub : public Base {
    public:
      virtual ByteVec decode_first_row(ByteVec row,
                                        uint32_t cols,
                                        byte bytes_per_pixel) const override;
      virtual ByteVec decode_row(ByteVec row,
                                  uint32_t cols,
                                  byte bytes_per_pixel,
                                  ByteVec prev_row) const override;
    };

    class Up : public Base {
    public:
      virtual ByteVec decode_first_row(ByteVec row,
                                        uint32_t cols,
                                        byte bytes_per_pixel) const override;
      virtual ByteVec decode_row(ByteVec row,
                                  uint32_t cols,
                                  byte bytes_per_pixel,
                                  ByteVec prev_row) const override;
    };

    class Average : public Base {
    public:
      virtual ByteVec decode_first_row(ByteVec row,
                                        uint32_t cols,
                                        byte bytes_per_pixel) const override;
      virtual ByteVec decode_row(ByteVec row,
                                  uint32_t cols,
                                  byte bytes_per_pixel,
                                  ByteVec prev_row) const override;
    };

    class Paeth : public Base {
    public:
      virtual ByteVec decode_first_row(ByteVec row,
                                        uint32_t cols,
                                        byte bytes_per_pixel) const override;
      virtual ByteVec decode_row(ByteVec row,
                                  uint32_t cols,
                                  byte bytes_per_pixel,
                                  ByteVec prev_row) const override;
    };

    const Base& get_filter(byte filter_sigil);

    namespace identity {
      constexpr None none = None{};
      constexpr Sub sub = Sub{};
      constexpr Up up = Up{};
      constexpr Average average = Average{};
      constexpr Paeth paeth = Paeth{};
    }
  }

  using Filter = filter::Base;
}

std::string to_string(png::FilterType ft);
std::ostream& operator<<(std::ostream& os, png::FilterType ft);
