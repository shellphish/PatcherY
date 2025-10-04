#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <vector>

#include "assert.hpp"
#include "png/chunk_factory.hpp"
#include "dimensions.hpp"
#include "hbytes.hpp"
#include "log.hpp"
#include "reader.hpp"

#include "png.hpp"

using namespace png;

Png::Png(std::istream& r) : file(r), factory(r) {
  std::vector<byte> raw_idat = image_data();

  factory.ihdr()->inspect(std::cerr);

  coder.load_image_data(raw_idat, *factory.ihdr(), factory.plte());
}

Png::~Png() {}

void Png::write(std::ostream& w) {
  w << "blah";
}

void Png::inspect(std::ostream& w) {
  w << "PNG" << std::endl;
  ihdr().inspect(w);
  factory.inspect(w);
  coder.inspect(w);
}

Dimensions Png::dimensions() const {
  return Dimensions(ihdr().cols, ihdr().rows);
}

Ihdr Png::ihdr() const {
  return *(factory.ihdr());
}

uint32_t Png::width() const {
  return ihdr().cols;
}

uint32_t Png::height() const {
  return ihdr().rows;
}

std::vector<byte> Png::image_data() const {
  return factory.image_data();
}

const std::vector<Rgba>& Png::pixels() const {
  return coder.to_pixels();
}
