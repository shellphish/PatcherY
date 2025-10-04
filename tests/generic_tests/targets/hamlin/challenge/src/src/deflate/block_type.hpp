#pragma once

#include <ostream>

#include "../hbytes.hpp"

namespace deflate {
  enum struct BlockType : byte {
                                uncompressed = 0,
                                fixed = 1,
                                dynamic = 2,
                                _reserved = 3
  };
}

std::ostream& operator<<(std::ostream& os, deflate::BlockType b);
std::string to_string(deflate::BlockType b);
