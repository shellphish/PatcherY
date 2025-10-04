#pragma once

#include "colorizer.hpp"

namespace png {
  namespace colorizer {
    class RgbColorizer : public Colorizer {
      virtual ~RgbColorizer() {};
      virtual std::vector<Rgba> colorize(std::vector<byte> image_bytes)
        const override;
    };
  }
}
