#include <array>
#include <cstdint>
#include <cctype>
#include <fstream>
#include <string>
#include <vector>

#include "assert.hpp"
#include "dimensions.hpp"
#include "hbytes.hpp"
#include "log.hpp"
#include "reader.hpp"
#include "rgba.hpp"

#include "ppm.hpp"

Ppm::Ppm(std::istream& r) {
  std::string magic;
  r >> magic;

  lll("ppm got magic %s want %s", magic.c_str(), "P6");
  assert("P6" == magic);

  r >> _width >> _height;
  r >> _maxval;

  r.get();

  assert(255 >= _maxval);

  _clamp = (byte)((uint32_t)256 / (_maxval + 1));

  lll("w %d h %d m %d c %d", _width, _height, _maxval, _clamp);

  load_pixels(r);
}

Ppm::Ppm(const Image& i) {
  _width = i.width();
  _height = i.height();
  _pixels = i.pixels();
  _maxval = 255;
  _clamp = 1;
}

uint32_t Ppm::width() const {
  return _width;
}

uint32_t Ppm::height() const {
  return _height;
}

const std::vector<Rgba>& Ppm::pixels() const {
  return _pixels;
}

Dimensions Ppm::dimensions() {
  return Dimensions{_width, _height};
}

void Ppm::inspect(std::ostream& w) {
  w << "PPM" << std::endl;

  w << "\tdimensions(" << dimensions() << ") maxval(" <<
    _maxval << ") pixel_count(" << _pixels.size() << ")" << std::endl;
}

void Ppm::write(std::ostream& w) {
  w << "P6" << std::endl << _width << " " << _height << std::endl
    << _maxval << std::endl;

  w.flush();

  for (Rgba px : _pixels) {
    w << px.r << px.g << px.b;
  }
  w <<  std::flush;
}

void Ppm::load_pixels(std::istream& r) {
  _pixels.reserve(_width * _height);
  lll("px %d", _pixels.size());
  for (uint32_t y = 0; y < _height; y++) {
    for (uint32_t x = 0; x < _width; x++) {
      _pixels.push_back(read_pixel(r));
    }
  }
}

Rgba Ppm::read_pixel(std::istream& r) {
  std::array<byte, 3> px;
  r.read((char*)(void*) px.data(), px.size());
  return Rgba{declamp(px)};
}

std::array<byte, 3> Ppm::declamp(std::array<byte, 3> b) {
  return {declamp(b[0]), declamp(b[1]), declamp(b[2])};
}

byte Ppm::declamp(byte b) {
  return (byte)(b * _clamp);
}
