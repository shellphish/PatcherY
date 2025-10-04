#pragma once

#include <vector>

#include "code.hpp"
#include "dynamic_code_code.hpp"
#include "dynamic_distance_code.hpp"

namespace deflate {
  class DynamicCode : public Code {
  public:
    DynamicCode(BitVector& reader) : decoder(reader) {};

    virtual const Destination& get_destination(CodeBits path);

    DynamicDistanceCode get_distance_code();
  private:
    dynamic_code_code::DCCDecoder decoder;
  };
}
