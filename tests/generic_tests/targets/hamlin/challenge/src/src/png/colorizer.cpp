#include "colorizer.hpp"
#include "rgb_colorizer.hpp"
#include "palette_colorizer.hpp"

#include "plte.hpp"

using namespace png;
using namespace png::colorizer;

colorizer::Base* png::colorizer::get_colorizer(Ihdr ihdr, Plte* plte) {
  switch (ihdr.color_type) {
  case ColorType::rgb:
    return new RgbColorizer();
  case ColorType::palette:
    assert(nullptr != plte);
    return new PaletteColorizer(*plte);
  default:
    assert(false);
  }
}
