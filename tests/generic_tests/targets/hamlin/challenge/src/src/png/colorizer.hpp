#pragma once

#include <vector>

#include "common.hpp"
#include "ihdr.hpp"
#include "plte.hpp"

namespace png {
  namespace colorizer {
    class Base {
    public:
      virtual std::vector<Rgba> colorize(std::vector<byte> image_bytes)
        const = 0;

      virtual ~Base() {};
    };

    Base* get_colorizer(Ihdr ihdr, Plte* plte);
  }
  using Colorizer = colorizer::Base;
}
