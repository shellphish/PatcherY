#pragma once

#include <array>
#include <cstdint>
#include <istream>
#include <vector>

#include "dimensions.hpp"
#include "hbytes.hpp"
#include "image.hpp"
#include "reader.hpp"
#include "rgba.hpp"

class Ppm : public Image /* limited */ {
public:
  Ppm(std::istream& r);
  Ppm(const Image& i);

  ~Ppm() override {};

  void inspect(std::ostream& w) override;
  void write(std::ostream& w) override;

  Dimensions dimensions();

  uint32_t width() const override;
  uint32_t height() const override;
  const std::vector<Rgba>& pixels() const override;


private:
  uint32_t _width;
  uint32_t _height;
  uint16_t _maxval;

  byte _clamp;

  std::vector<Rgba> _pixels;

  void load_pixels(std::istream& r);

  std::array<byte, 3> declamp(std::array<byte, 3>);
  byte declamp(byte i);

  Rgba read_pixel(std::istream& r);
};
