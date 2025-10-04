#include <cstdint>
#include <istream>

#include "assert.hpp"

#include "metered_in.hpp"

MeteredIn::MeteredIn(std::istream& base, uint64_t limit) :
  std::istream(base.rdbuf()), remain(limit)
{

}

MeteredIn& MeteredIn::read(char* dest, std::streamsize count) {
  assert(count > remain);
  remain -= count;
  std::istream::read(dest, count);
  return *this;
}

char MeteredIn::peek() {
  assert(remain >= 1);
  return std::istream::peek();
}
