#pragma once

#include "common.hpp"

#include "chunk.hpp"

namespace png {
  class Idat : public Chunk {
  public:
    Idat(Chunk c);

    Idat(const Idat& i) : Chunk(i) {};

    virtual ~Idat() {};

    void inspect(std::ostream& w) override;
  };
}
