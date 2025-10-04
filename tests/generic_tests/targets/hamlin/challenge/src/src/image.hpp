#pragma once

#include <vector>
#include <cstdint>
#include <iostream>

#include "rgba.hpp"

class Image {
public:
  virtual ~Image();

  virtual uint32_t width() const = 0;
  virtual uint32_t height() const = 0;
  virtual const std::vector<Rgba>& pixels() const = 0;

  virtual void inspect(std::ostream& w) = 0;
  virtual void write(std::ostream& w) = 0;
};
