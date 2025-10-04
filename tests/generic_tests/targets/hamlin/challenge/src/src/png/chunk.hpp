#pragma once

#include <string>
#include <vector>

#include "common.hpp"

namespace png {
  class Chunk {
  public:
    Chunk(std::istream& r);
    Chunk(const Chunk& c) : length(c.length), type(c.type),
                            data(c.data), crc(c.crc) {};
    Chunk() : length(0), type('__PH'),
              data({}), crc(0) {};
    virtual ~Chunk() {};

    virtual void inspect(std::ostream& w);

    void assert_crc();

    std::string type_string();

    uint32_t length = 0;
    uint32_t type;
    std::vector<byte> data;
    uint32_t crc;
  };
}
