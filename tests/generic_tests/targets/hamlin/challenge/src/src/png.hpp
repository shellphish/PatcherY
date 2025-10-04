#pragma once

#include <cstdint>
#include <vector>

#include "dimensions.hpp"
#include "hbytes.hpp"
#include "image.hpp"
#include "reader.hpp"

#include "png/chunk.hpp"
#include "png/chunk_factory.hpp"
#include "png/file.hpp"
#include "png/idat.hpp"
#include "png/ihdr.hpp"
#include "png/image_coder.hpp"

using Chunk = png::Chunk;
using ChunkFactory = png::ChunkFactory;
using File = png::File;
using Idat = png::Idat;
using Ihdr = png::Ihdr;
using ImageCoder = png::ImageCoder;

class Png : public Image {
public:
  Png(std::istream& r);
  Png(const Image& i);

  ~Png() override;

  void inspect(std::ostream& w) override;
  void write(std::ostream& w) override;
  byte bytes_per_pixel() const;

  Dimensions dimensions() const;

  uint32_t width() const override;
  uint32_t height() const override;
  const std::vector<Rgba>& pixels() const override;

  std::vector<byte> image_data() const;

private:

  File file;
  ChunkFactory factory;
  ImageCoder coder;
  Ihdr ihdr() const;
  std::vector<Idat> idat;
};
