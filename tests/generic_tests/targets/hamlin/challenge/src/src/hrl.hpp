#pragma once

#include <istream>

#include "dimensions.hpp"
#include "image.hpp"
#include "rgba.hpp"
#include "reader.hpp"

class Hrl : public Image {
public:
  Hrl(std::istream& r);
  Hrl(const Image& i);

  ~Hrl() override;

  void inspect(std::ostream& w) override;
  void write(std::ostream& w) override;

  Dimensions dimensions() const;

  uint32_t width() const override;
  uint32_t height() const override;
  const std::vector<Rgba>& pixels() const override;

private:
  uint32_t _width;
  uint32_t _height;

  std::vector<Rgba> _pixels;

  byte _sigil;

  byte determine_sigil();

  void read_pixels(std::istream& r);
};
