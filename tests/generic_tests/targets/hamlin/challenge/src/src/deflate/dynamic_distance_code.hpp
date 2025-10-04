#pragma once

#include "common.hpp"

#include "canonical_code.hpp"
#include "distance_code.hpp"

namespace deflate {
  class DynamicDistanceCode : public DistanceCode {
  public:
    DynamicDistanceCode(CanonicalCode dc) : dist_codes(dc) {};

    virtual const DistanceDestination& get_destination(CodeBits path);

  private:
    CanonicalCode dist_codes;
  };
}
