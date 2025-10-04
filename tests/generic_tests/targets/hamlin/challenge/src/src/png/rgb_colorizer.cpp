#include "rgb_colorizer.hpp"

using namespace png::colorizer;

std::vector<Rgba> RgbColorizer::colorize(std::vector<byte> image_bytes) const {
    std::vector<Rgba> out_px{};
    assert((image_bytes.size() % 3) == 0);
    std::size_t cols = image_bytes.size() / 3;
    out_px.reserve(cols);

    for (std::size_t i = 0; i < cols; i++) {
        std::size_t offset = (i * 3);

        byte pal_idx_r = image_bytes[offset + 0];
        byte pal_idx_g = image_bytes[offset + 1];
        byte pal_idx_b = image_bytes[offset + 2];

        out_px.push_back({pal_idx_r, pal_idx_g, pal_idx_b});
    }

    return out_px;
}
