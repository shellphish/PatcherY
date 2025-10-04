#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <sstream>

#include "assert.hpp"
#include "log.hpp"
#include "hrl.hpp"
#include "hton.hpp"
#include "inflate.hpp"
#include "png.hpp"
#include "ppm.hpp"

using std::string;

int main() {
  std::ifstream in("/mnt/pov/images/fun.png",
                   std::ios::binary | std::ios::ate);
  in.seekg(0);

  Png png = Png(in);

  png.inspect(std::cerr);

  std::ofstream out("/mnt/challenge/tmp/idat.deflate",
                    std::ios::binary | std::ios::trunc);
  std::vector<byte> id = png.image_data();
  out.write((char*)(void*)id.data(), id.size());
  out.close();

  Ppm hrl = Ppm(png);

  hrl.inspect(std::cerr);

  std::ofstream ppmout("/mnt/challenge/tmp/pngtest.ppm",
                       std::ios::binary | std::ios::trunc);
  hrl.write(ppmout);
  ppmout.close();

  return 0;
}
