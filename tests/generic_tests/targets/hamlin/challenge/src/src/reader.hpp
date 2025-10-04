#pragma once

#include <array>
#include <cstdint>
#include <fstream>
#include <vector>

#include "hbytes.hpp"

class Reader {
public:
  Reader(std::istream& r) : reader(r) {};

  template <std::size_t count>
  void read_ba(std::array<byte, count>& buf);

  uint32_t read_l();
  std::vector<byte> read_bv(uint32_t length);

  bool eof();

  template <typename T>
  friend Reader operator>>(const Reader& lhs, const T rhs);

private:
  std::istream& reader;
};

template <typename T>
Reader operator>>(const Reader& lhs, const T rhs) {
  lhs.reader >> rhs;
  return lhs;
}
