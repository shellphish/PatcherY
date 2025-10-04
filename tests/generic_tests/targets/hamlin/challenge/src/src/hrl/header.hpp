#pragma once

#include "common.hpp"

namespace hrl {
  class Header {
  public:
    Header(std::istream& r);
    Header(uint32_t w, uint32_t h, uint32_t s) :
      width(w), height(h), sigil(s) {};
    Header(const Header& o) :
      width(o.width), height(o.height), sigil(o.sigil) {};

    uint32_t width;
    uint32_t height;
    byte sigil;

    void write(std::ostream& o);

  private:
    struct __attribute__((packed)) Pack {
      uint32_t magic;
      uint32_t width;
      uint32_t height;
      byte sigil;
    };

    static_assert(sizeof(Pack) == 13);
  };
}
