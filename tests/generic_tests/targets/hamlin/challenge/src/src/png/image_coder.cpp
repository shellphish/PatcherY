#include <ostream>

#include "common.hpp"

#include "colorizer.hpp"
#include "image_coder.hpp"
#include "filter.hpp"
#include "../inflate.hpp"
#include "../deflate/zlib_header.hpp"

using namespace png;

using ZlibHeader = deflate::ZlibHeader;

void ImageCoder::load_image_data(std::vector<byte> image_data,
                                 Ihdr ihdr,
                                 Plte* plte) {
  BitVector bv = {image_data};
  zlh = new ZlibHeader(bv);
  zlh->inspect(std::cerr);
  bv.inspect(std::cerr);

  Inflate inflater = {*zlh, bv};

  std::vector<byte> inflated_data = inflater.inflated();

  std::ofstream inflated_dump("/mnt/challenge/tmp/idat.idat",
                              std::ios::binary | std::ios::trunc);
  inflated_dump.write((char*)(void*) inflated_data.data(),
                      inflated_data.size());
  inflated_dump.close();

  assert(0 == (ihdr.bit_depth % 8));

  byte bytes_per_channel = ihdr.bit_depth / 8;

  byte bytes_per_pixel = 0;

  switch (ihdr.color_type) {
  case ColorType::rgb:
    bytes_per_pixel = 3 * bytes_per_channel;
    break;
  case ColorType::rgba:
    bytes_per_pixel = 4 * bytes_per_channel;
    break;
  case ColorType::palette:
    bytes_per_pixel = 1;
    break;
  default:
    assert(false);
  }

  std::size_t bytes_per_row = 1 + (ihdr.cols * bytes_per_pixel);
  std::size_t expected_total_bytes = bytes_per_row * ihdr.rows;

  assert(inflated_data.size() == expected_total_bytes);

  std::vector<byte> prev_row{};
  std::vector<Rgba> pixel_row{};

  prev_row.reserve(ihdr.cols * bytes_per_pixel);
  pixel_row.reserve(ihdr.cols);

  Colorizer* colorizer = colorizer::get_colorizer(ihdr, plte);

  for(int r = 0; r < ihdr.rows; r++) {
    std::size_t offset = r * bytes_per_row;
    std::vector<byte> row_data{};

    byte filter_sigil = inflated_data[offset];

    auto offset_start = inflated_data.begin() + offset + 1;
    auto offset_end = offset_start + bytes_per_row - 1;

    row_data.insert(row_data.end(), offset_start, offset_end);

    const Filter& f = filter::get_filter(filter_sigil);




    std::vector<byte> cur_row{};


    if (0 == r) {
      cur_row = f.decode_first_row(row_data, ihdr.cols, bytes_per_pixel);
    } else {
      cur_row = f.decode_row(row_data, ihdr.cols, bytes_per_pixel, prev_row);
    }

    pixel_row = colorizer->colorize(cur_row);

    pixels.insert(pixels.end(), pixel_row.begin(), pixel_row.end());
    prev_row = cur_row;
  }

  delete colorizer;
}

void ImageCoder::inspect(std::ostream& w) {
  w << "ImageCoder" << std::endl;
  w << "\timage_data<byte>(" << image_data.size()
    << ") pixels<Rgba>(" << pixels.size() << ")" << std::endl;
  if (nullptr != zlh) {
    w << "\tZlibHeader ";
    zlh->inspect(w);
    w << std::endl;
  }
}

const std::vector<Rgba>& ImageCoder::to_pixels() const {
  return pixels;
}
