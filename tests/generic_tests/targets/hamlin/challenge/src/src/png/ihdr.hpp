#pragma once

#include "common.hpp"

#include "chunk.hpp"
#include "colortype.hpp"

namespace png {
  class Ihdr : public Chunk {
  public:
    Ihdr(Chunk c);

    Ihdr(const Ihdr& i) : Chunk(i), cols(i.cols), rows(i.rows),
                          bit_depth(i.bit_depth), color_type(i.color_type),
                          compression(i.compression), filter(i.filter),
                          interlace(i.interlace) {};

    Ihdr() : Chunk(), cols(0), rows(0), bit_depth(0), color_type(_invalid),
             compression(255), filter(255), interlace(255) {};

    virtual ~Ihdr() {};

    void inspect(std::ostream& w) override;

    Dimensions dimensions();

    uint32_t cols; // width
    uint32_t rows; // height
    uint8_t bit_depth;
    png::ColorType color_type;
    uint8_t compression;
    uint8_t filter;
    uint8_t interlace;

  private:
    struct __attribute__((packed)) Pack {
      uint32_t cols; // width
      uint32_t rows; // height
      uint8_t bit_depth;
      uint8_t  color_type;
      uint8_t compression;
      uint8_t filter;
      uint8_t interlace;
    };
  };
}
