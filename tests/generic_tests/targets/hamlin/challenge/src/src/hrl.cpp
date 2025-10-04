#include <istream>

#include "assert.hpp"
#include "log.hpp"
#include "reader.hpp"

#include "hrl/header.hpp"
#include "hrl/pixel.hpp"
#include "hrl/run.hpp"

#include "hrl.hpp"

using namespace hrl;

Hrl::Hrl(std::istream& r) {

  Header head(r);

  _width = head.width;
  _height = head.height;

  _sigil = head.sigil;

  read_pixels(r);
}

Hrl::Hrl(const Image& i) :
_width(i.width()), _height(i.height()), _pixels(i.pixels())
{
  _sigil = determine_sigil();
}

Hrl::~Hrl() {};

void Hrl::write(std::ostream& o) {
  hrl::Header head(_width, _height, _sigil);
  head.write(o);

  uint64_t total_pixels = _height * _width;
  uint64_t current_pixel = 0;

  while (total_pixels > current_pixel) {
    Rgba cur_color = _pixels[current_pixel];
    if ((current_pixel + 1) < _pixels.size()) {

      Rgba next_color = _pixels[current_pixel + 1];

      if (cur_color == next_color) {
        byte run_count = 1;
        while (cur_color == next_color) {
          run_count++;
          if (255 == run_count) break;
          if (total_pixels <= current_pixel + run_count) break;
          next_color = _pixels[current_pixel + run_count];
        }




        Run r{_sigil, run_count, cur_color.r, cur_color.g, cur_color.b};
        o.write((char*)(void*)&r, sizeof(r));
        current_pixel += run_count;
        continue;
      }
    }

    if (_sigil == cur_color.r) {



      Run r{_sigil, 1, cur_color.r, cur_color.g, cur_color.b};
      o.write((char*)(void*)&r, sizeof(r));
      current_pixel += 1;
      continue;
    }


    Pixel p{cur_color.r, cur_color.g, cur_color.b};
    o.write((char*)(void*)&p, sizeof(p));
    current_pixel += 1;
  }
}

void Hrl::inspect(std::ostream& w) {
  w << "HRL" << std::endl;

  w << "\tdimensions(" << dimensions() << ") sigil(" << _sigil <<
    ")" << std::endl;
}

Dimensions Hrl::dimensions() const {
  return Dimensions(_width, _height);
}

uint32_t Hrl::width() const {
  return _width;
}

uint32_t Hrl::height() const {
  return _height;
}

const std::vector<Rgba>& Hrl::pixels() const {
  return _pixels;
}

byte Hrl::determine_sigil() {
  std::array<uint32_t, 256> red_counts = {0};

  for (Rgba px : _pixels) {
    red_counts[px.r]++;
  }

  uint32_t least_popular_count = _width * _height;
  uint32_t least_popular_value = 0;

  for (uint32_t val = 0; val < 256; val++) {
    uint32_t cnt = red_counts[val];
    if (cnt < least_popular_count) {
      least_popular_count = cnt;
      least_popular_value = val;
    }
  }

  lll("sigil %d with count %d", least_popular_value, least_popular_count);

  return least_popular_value;
}

void Hrl::read_pixels(std::istream& r) {
  uint32_t pixel_count = _width * _height;

  _pixels.clear();
  _pixels.reserve(pixel_count);

  uint32_t remaining_pixels = pixel_count;

  while (remaining_pixels > 0) {
    byte sentry = static_cast<byte>(r.peek());

    if (_sigil == sentry) {
      Run run;
      r.read((char*)(void*) &run, sizeof(run));
      Rgba px(run.r, run.g, run.b);
      for (byte c = 0; c < run.length; c++) {
        _pixels.push_back(px);
      }

      remaining_pixels -= run.length;
    } else {
      Pixel pxl;
      r.read((char*)(void*) &pxl, sizeof(pxl));
      _pixels.push_back({pxl.r, pxl.g, pxl.b});

      remaining_pixels -= 1;
    }
  }
}
