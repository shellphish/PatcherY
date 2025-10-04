#pragma once

#include "colorizer.hpp"
#include "plte.hpp"

namespace png {
  namespace colorizer {
    class PaletteColorizer : public Colorizer  {
    public:
      PaletteColorizer(Plte plte) : palette(plte) {};
      virtual ~PaletteColorizer() {};

      virtual std::vector<Rgba> colorize(std::vector<byte> image_bytes)
        const override;

    private:
      Plte palette;
    };
  }
}
