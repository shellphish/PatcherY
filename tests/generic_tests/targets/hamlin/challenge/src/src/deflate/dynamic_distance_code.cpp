#include "dynamic_distance_code.hpp"

#include "fixed_distance_code.hpp"

using namespace deflate;
using namespace deflate::distance_destination::identity;

const DistanceDestination& DynamicDistanceCode::get_destination(CodeBits path) {
  if (dist_codes.need_more_bits(path)) return incomplete;
  if (!dist_codes.is_valid_code(path)) return invalid;

  uint16_t distance_symbol = dist_codes.get_symbol(path);

  const DistanceDestination& dest =
    fixed_distance_code::distance_table[distance_symbol];

  return dest;
}
