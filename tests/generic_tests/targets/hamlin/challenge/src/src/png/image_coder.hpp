#pragma once

#include "common.hpp"
#include "ihdr.hpp"
#include "plte.hpp"
#include "../deflate/zlib_header.hpp"

namespace png {
  class ImageCoder {
  public:
    void load_image_data(std::vector<byte> image_data,
                         Ihdr ihdr,
                         Plte* plte);
    void load_pixels(std::vector<Rgba> pixels,
                     Ihdr ihdr);

    std::vector<byte> to_image_data();
    const std::vector<Rgba>& to_pixels() const;

    void inspect(std::ostream& w);

  private:
    std::vector<byte> image_data = {};
    std::vector<Rgba> pixels = {};

    deflate::ZlibHeader* zlh = nullptr;
  };
}
