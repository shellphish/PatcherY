#include <arpa/inet.h>
#include <fstream>

#include "hbytes.hpp"

#include "reader.hpp"

template <std::size_t count>
void Reader::read_ba(std::array<byte, count>& buf) {
  char* cb = (char*)(void*) buf.data();
  reader.read(cb, count);
}

uint32_t Reader::read_l() {
  uint32_t buf;
  reader.read((char*)(void*) &buf, sizeof(buf));
  return ntohl(buf);
}

std::vector<byte> Reader::read_bv(uint32_t length) {
  std::vector<byte> buf(length);
  reader.read((char*)(void*) buf.data(), length);

  return buf;
}

bool Reader::eof() {
  reader.peek();
  return reader.eof();
}
