#include "dynamic_code.hpp"

using namespace deflate;
using namespace deflate::destination;

const Destination& DynamicCode::get_destination(CodeBits path) {
  CanonicalCode& code = decoder.literal_codes;

  if (code.need_more_bits(path)) return identity::incomplete;
  if (!code.is_valid_code(path)) return identity::invalid;

  uint16_t symbol = code.get_symbol(path);

  assert(symbol < fixed_destinations.size());
  return *fixed_destinations[symbol];
}

DynamicDistanceCode DynamicCode::get_distance_code() {
  return {decoder.distance_codes};
}
