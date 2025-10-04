#pragma once

#include "common.hpp"

#include "chunk.hpp"

namespace png {
  class Iend : public Chunk {
  public:
    Iend(Chunk c);

    virtual ~Iend() {};
  };
}
