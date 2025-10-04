#pragma once

#include <cstdint>
#include <fstream>

namespace png {
  enum ColorType : uint8_t {
                            greyscale = 0,
                            rgb = 2,
                            palette = 3,
                            greyscale_alpha = 4,
                            rgba = 6,
                            _invalid = 255

  };
}

std::ostream& operator<<(std::ostream& os, png::ColorType c);
