#pragma once

#include "common.hpp"

#include "chunk.hpp"
#include "plte.hpp"

namespace png {
  class Plte : public Chunk {
  public:
    Plte(Chunk c);

    Plte(const Plte& i) :
      Chunk(i), palette(i.palette), entry_count(i.entry_count) {};

    virtual ~Plte() {};

    Rgba operator[](byte pal_idx) const;

    void inspect(std::ostream& w) override;

  private:
    std::vector<Rgba> palette = {};
    std::size_t entry_count = 0;
  };
}
