#include "fixed_distance_code.hpp"

using namespace deflate;
using namespace deflate::fixed_distance_code;

const DistanceDestination& FixedDistanceCode::get_destination(CodeBits path) {
  if (path.len < 5) {
    return distance_destination::identity::incomplete;
  }
  if (path.len > 5) {
    return distance_destination::identity::invalid;
  }

  uint16_t maybe_sym = code_to_sym[path.bits];
  byte maybe_len = lengths[maybe_sym];
  uint16_t back_code = codes[maybe_sym];

  if ((path.len == maybe_len) && (path.bits == back_code)) {
    return distance_table[maybe_sym];
  }

  return distance_destination::identity::invalid;
}
