#include "palette_colorizer.hpp"

using namespace png;
using namespace png::colorizer;

std::vector<Rgba> PaletteColorizer::colorize(std::vector<byte> image_bytes)
  const {
    std::vector<Rgba> out_px{};
    out_px.reserve(image_bytes.size());

    for (std::size_t i = 0; i < image_bytes.size(); i++) {
        byte pal_idx = image_bytes[i];
        Rgba color = palette[pal_idx];
        out_px.push_back(color);
    }

    return out_px;
}
