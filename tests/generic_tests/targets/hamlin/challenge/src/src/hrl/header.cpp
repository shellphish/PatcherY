#include <arpa/inet.h>

#include "common.hpp"

#include "header.hpp"

using namespace hrl;

const uint32_t expected_magic = 'HRLe';

Header::Header(std::istream& r) {
  Pack p;
  r.read((char*)(void*)(&p), sizeof(p));

  lll("hrl got magic (net %x host %x) want %x", p.magic, ntoh(p.magic), expected_magic);

  assert(expected_magic == ntohl(p.magic));
  width = ntohl(p.width);
  height = ntohl(p.height);
  sigil = p.sigil;
}

void Header::write(std::ostream& o) {
  Pack p;
  p.magic = htonl(expected_magic);
  p.width = htonl(width);
  p.height = htonl(height);
  p.sigil = sigil;

  o.write((char*)(void*)(&p), sizeof(p));
}
