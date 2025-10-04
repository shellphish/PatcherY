#include <cmath>

#include "common.hpp"

#include "filter.hpp"

using namespace png;
using namespace png::filter;
using namespace png::filter::identity;

const Base& png::filter::get_filter(byte filter_sigil) {
  FilterType type = (FilterType)filter_sigil;
  switch (type) {
  case FilterType::none:
    return none;
  case FilterType::sub:
    return sub;
  case FilterType::up:
    return up;
  case FilterType::average:
    return average;
  case FilterType::paeth:
    return paeth;
  default:
    assert(false);
  }
}

std::string to_string(png::FilterType ft) {
  switch (ft) {
  case FilterType::none:
    return "none";
  case FilterType::sub:
    return "sub";
  case FilterType::up:
    return "up";
  case FilterType::average:
    return "average";
  case FilterType::paeth:
    return "paeth";
  default:
    return "unknown filtertype";
  }
}

std::ostream& operator<<(std::ostream& os, png::FilterType ft) {
  os << to_string(ft);
  return os;
}

ByteVec None::decode_first_row(ByteVec row,
                               uint32_t cols,
                               byte bytes_per_pixel) const {
  ByteVec out_px{};
  out_px.reserve(cols * bytes_per_pixel);

  for (uint32_t i = 0; i < cols; i++) {
    std::size_t offset = i * bytes_per_pixel;
    for (byte j = 0; j < bytes_per_pixel; j++) {
      out_px.push_back(row[offset+j]);
    }
  }

  return out_px;
}

ByteVec None::decode_row(ByteVec row,
                         uint32_t cols,
                         byte bytes_per_pixel,
                         ByteVec _prev_row) const {
  return decode_first_row(row, cols, bytes_per_pixel);
}

ByteVec Sub::decode_first_row(ByteVec row,
                              uint32_t cols,
                              byte bytes_per_pixel) const {
  ByteVec out_px{};
  out_px.reserve(cols * bytes_per_pixel);

  for (uint32_t i = 0; i < cols; i++) {
    std::size_t offset = i * bytes_per_pixel;
    for (byte j = 0; j < bytes_per_pixel; j++) {
      std::size_t inner_offset = offset + j;
      byte diff = row[inner_offset];
      byte orig = 0;

      if (0 != i) {
        orig = out_px[inner_offset - bytes_per_pixel];
      }

      out_px.push_back(diff + orig);
    }
  }

  return out_px;
}

ByteVec Sub::decode_row(ByteVec row,
                        uint32_t cols,
                        byte bytes_per_pixel,
                        ByteVec _prev_row) const {
  return decode_first_row(row, cols, bytes_per_pixel);
}

ByteVec Up::decode_first_row(ByteVec row,
                              uint32_t cols,
                              byte bytes_per_pixel) const {
  ByteVec fake_prev_row{};
  fake_prev_row.resize(cols * bytes_per_pixel, 0);
  return decode_row(row, cols, bytes_per_pixel, fake_prev_row);
}

ByteVec Up::decode_row(ByteVec row,
                        uint32_t cols,
                        byte bytes_per_pixel,
                        ByteVec prev_row) const {
  ByteVec out_px{};
  out_px.reserve(cols * bytes_per_pixel);

  for (uint32_t i = 0; i < cols; i++) {
    std::size_t offset = (i * bytes_per_pixel);
    for (byte j = 0; j < bytes_per_pixel; j++) {
      std::size_t inner_offset = offset + j;
      byte diff = row[inner_offset];
      byte orig = prev_row[inner_offset];

      out_px.push_back(diff + orig);
    }
  }

  return out_px;
}

ByteVec Average::decode_first_row(ByteVec row,
                                   uint32_t cols,
                                   byte bytes_per_pixel) const {
  ByteVec fake_prev_row{};
  fake_prev_row.resize(cols * bytes_per_pixel, 0);
  return decode_row(row, cols, bytes_per_pixel, fake_prev_row);
}

ByteVec Average::decode_row(ByteVec row,
                             uint32_t cols,
                             byte bytes_per_pixel,
                             ByteVec prev_row) const {
  ByteVec out_px{};
  out_px.reserve(cols * bytes_per_pixel);

  for (uint32_t i = 0; i < cols; i++) {
    std::size_t offset = (i * bytes_per_pixel);
    for (byte j = 0; j < bytes_per_pixel; j++) {
      std::size_t inner_offset = offset + j;
      uint16_t diff = row[inner_offset];
      uint16_t up = prev_row[inner_offset];
      uint16_t left = 0;
      if (0 != i) {
        left = out_px[inner_offset - bytes_per_pixel];
      }

      uint16_t calc = (up + left) >> 1;
      assert(256 > calc);
      byte result = (byte)(diff + calc);
      out_px.push_back(result);
    }
  }
  return out_px;
}

byte paeth_predictor(byte a, byte b, byte c) {
  int16_t p = a + b - c;
  int16_t pa = std::abs((int16_t)p - (int16_t)a);
  int16_t pb = std::abs((int16_t)p - (int16_t)b);
  int16_t pc = std::abs((int16_t)p - (int16_t)c);

  if ((pa <= pb) && (pa <= pc)) return a;
  if (pb <= pc) return b;
  return c;
}

ByteVec Paeth::decode_first_row(ByteVec row,
                                 uint32_t cols,
                                 byte bytes_per_pixel) const {
  ByteVec fake_prev_row{};
  fake_prev_row.resize(cols * bytes_per_pixel, 0);
  return decode_row(row, cols, bytes_per_pixel, fake_prev_row);
}

ByteVec Paeth::decode_row(ByteVec row,
                           uint32_t cols,
                           byte bytes_per_pixel,
                           ByteVec prev_row) const {
  ByteVec out_px{};
  out_px.reserve(cols * bytes_per_pixel);

  for (uint32_t i = 0; i < cols; i++) {
    std::size_t offset = (i * bytes_per_pixel);
    for (byte j = 0; j < bytes_per_pixel; j++) {
      std::size_t inner_offset = offset + j;
      byte diff = row[inner_offset];
      byte up = prev_row[inner_offset];
      byte left = 0;
      byte upleft = 0;
      if (0 != i) {
        std::size_t left_offset = inner_offset - bytes_per_pixel;
        left = out_px[left_offset];
        upleft = prev_row[left_offset];
      }

      byte calc = paeth_predictor(left, up, upleft);

      out_px.push_back(diff + calc);
    }
  }
  return out_px;
}
