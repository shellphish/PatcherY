#pragma once

#include "distance_destination.hpp"

namespace deflate {
  class DistanceCode {
  public:
    virtual const DistanceDestination& get_destination(CodeBits path) = 0;
  };
}
