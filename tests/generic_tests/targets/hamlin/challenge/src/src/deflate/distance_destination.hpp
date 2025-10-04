#pragma once

#include <array>
#include <ostream>

#include "bit_vector.hpp"
#include "common.hpp"

namespace deflate {
  class DistanceDestination {
  public:
    byte extra;
    uint16_t min;

    const static byte INCOMPLETE_EXTRA = 254;
    const static byte INVALID_EXTRA = 255;

    constexpr DistanceDestination() : extra(0), min(0) {};
    constexpr DistanceDestination(byte e, uint16_t m) : extra(e), min(m) {};
    constexpr DistanceDestination(const DistanceDestination& other) :
      extra(other.extra), min(other.min) {};

    constexpr bool operator==(const DistanceDestination& other) const {
      if (extra != other.extra) return false;
      if (min != other.min) return false;

      return true;
    }

    constexpr bool is_complete() const {
      if (extra < INCOMPLETE_EXTRA) return true;
      return false;
    }

    constexpr bool is_incomplete() const {
      if (extra == INCOMPLETE_EXTRA) return true;
      return false;
    }

    constexpr bool is_invalid() const {
      if (extra == INVALID_EXTRA) return true;
      return false;
    }

    void inspect(std::ostream& o) const;
  };

  namespace distance_destination {
    namespace identity {
      constexpr DistanceDestination
        incomplete{DistanceDestination::INCOMPLETE_EXTRA, 0};
      constexpr DistanceDestination
        invalid{DistanceDestination::INVALID_EXTRA, 0};

      static_assert(incomplete.is_incomplete());
      static_assert(invalid.is_invalid());
      static_assert(!incomplete.is_complete());
      static_assert(!invalid.is_complete());
    }
  }
}
