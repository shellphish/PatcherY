#pragma once

#include "common.hpp"

#include "code.hpp"
#include "canonical_code.hpp"

namespace deflate {
  namespace dynamic_code_code {
    class DCCDecoder {
    public:
      DCCDecoder(BitVector& reader);

      CanonicalCode literal_codes;
      CanonicalCode distance_codes;

      uint16_t get_symbol(CodeBits symbol);
    private:
      uint16_t hlit;
      byte hdist;
      byte hclen;

      uint16_t total_codes;

    };
  }
}
