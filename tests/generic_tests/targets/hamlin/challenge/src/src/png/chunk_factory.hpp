#pragma once

#include <map>

#include "common.hpp"

#include "chunk.hpp"
#include "ihdr.hpp"
#include "idat.hpp"
#include "iend.hpp"
#include "plte.hpp"

namespace png {
  class ChunkFactory {
  public:
    ChunkFactory(std::istream& r);
    ~ChunkFactory();

    void inspect(std::ostream& w);

    std::vector<Chunk*> chunks;

    Ihdr* ihdr() const;
    std::vector<Idat*> idat() const;

    Plte* plte() const;

    std::vector<byte> image_data() const;

  private:
    void materialize_chunks();

  };
}
