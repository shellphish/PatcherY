#pragma once

#include <vector>

#include "deflate/bit_vector.hpp"
#include "deflate/code.hpp"
#include "deflate/distance_code.hpp"
#include "deflate/history.hpp"
#include "deflate/array_history.hpp"
#include "deflate/vector_history.hpp"
#include "deflate/zlib_header.hpp"

using deflate::BitVector;
using deflate::Code;
using deflate::DistanceCode;
using deflate::History;
using deflate::ZlibHeader;

class Inflate {
public:
  Inflate(ZlibHeader zlh, BitVector& b);
  ~Inflate() {
    if (nullptr != history) delete history;
  }

  std::vector<byte> inflated();
private:
  ZlibHeader header;
  BitVector& compressed;
  std::vector<byte> _inflated = {};
  History* history = nullptr;

  void inflate();

  void inflate_uncompressed();
  void inflate_fixed();
  void inflate_dynamic();

  void inflate_code(Code& code, DistanceCode& dist_code);
};
