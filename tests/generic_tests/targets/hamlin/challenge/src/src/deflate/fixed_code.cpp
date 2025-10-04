#include "fixed_code.hpp"

using namespace deflate;
using namespace deflate::fixed_code;

const Destination& FixedCode::get_destination(const CodeBits path) {
  if (path.len < 7) return destination::identity::incomplete;
  if (path.len > 9) return destination::identity::invalid;

  uint16_t maybe_sym = code_to_sym[path.bits];
  byte maybe_len = lengths[maybe_sym];
  uint16_t back_code = codes[maybe_sym];

  if ((path.len == maybe_len) && (path.bits == back_code)) {
    return *destination::fixed_destinations[maybe_sym];
  }

  return destination::identity::incomplete;
}
