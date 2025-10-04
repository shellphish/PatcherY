#include "vector_history.hpp"

using namespace deflate;

VectorHistory::VectorHistory(ZlibHeader& zlh) : header(zlh) {
  buf.resize(header.window_size());
}

void VectorHistory::append(byte b) {
  buf[cursor] = b;
  cursor = (cursor + 1) % buf.size();
}

std::vector<byte> VectorHistory::copy(uint32_t dist, uint16_t count) {
  std::ptrdiff_t start_cur = (cursor - dist) % buf.size();
  std::ptrdiff_t end_cur = start_cur + count;

  std::vector<byte> cpy{};
  cpy.reserve(count);

  for (std::size_t n = start_cur; n < end_cur; n++) {
    byte b = buf[n % MAX_HISTORY];
    append(b);
    cpy.push_back(b);
  }

  return cpy;
}
