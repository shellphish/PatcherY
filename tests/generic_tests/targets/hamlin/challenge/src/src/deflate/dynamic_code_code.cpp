#include "common.hpp"

#include "dynamic_code_code.hpp"

#include "canonical_code.hpp"
#include "history.hpp"

using namespace deflate;
using namespace deflate::dynamic_code_code;

DCCDecoder::DCCDecoder(BitVector& reader) {
  hlit = reader.read_bits(5) + 257;
  hdist = reader.read_bits(5) + 1;
  hclen = reader.read_bits(4) + 4;

  total_codes = hlit + hdist;

  std::array<byte, 19> code_len_code_lens{};
  code_len_code_lens.fill(0);
  std::array<byte, 19> code_len_read_order = {16, 17, 18,
                                              0, 8, 7, 9, 6, 10, 5, 11,
                                              4, 12, 3, 13, 2, 14, 1, 15};

  for (byte n = 0; n < hclen; n++) {
    std::size_t idx = code_len_read_order[n];
    code_len_code_lens[idx] = reader.read_bits(3);
  }

  CanonicalCode code_len_code =
    CanonicalCode::create_from_array<19>(code_len_code_lens);

  std::vector<uint16_t> lit_code_lens;
  lit_code_lens.reserve(hlit);

  while (lit_code_lens.size() < hlit) {
    uint16_t symbol = code_len_code.get_next_symbol(reader);
    if (16 > symbol) {
      lit_code_lens.push_back(symbol);
    } else if (16 == symbol) {
      assert(lit_code_lens.size() > 0);
      byte run = reader.read_bits(2) + 3;
      byte prev = lit_code_lens[lit_code_lens.size() - 1];
      for(byte c = 0; c < run; c++) {
        lit_code_lens.push_back(prev);
      }
    } else if (17 == symbol) {
      byte run = reader.read_bits(3) + 3;
      for (byte c = 0; c < run; c++) {
        lit_code_lens.push_back(0);
      }
    } else if (18 == symbol) {
      byte run = reader.read_bits(7) + 11;
      for (byte c = 0; c < run; c++) {
        lit_code_lens.push_back(0);
      }
    } else {
      assert(symbol <= 18);
    }
  }

  assert(lit_code_lens.size() == hlit);

  literal_codes = {lit_code_lens};

  std::vector<uint16_t> dist_code_lens;
  dist_code_lens.reserve(hdist);

  while (dist_code_lens.size() < hdist) {
    uint16_t symbol = code_len_code.get_next_symbol(reader);
    if (16 > symbol) {
      dist_code_lens.push_back(symbol);
    } else if (16 == symbol) {
      assert(dist_code_lens.size() > 0);
      byte run = reader.read_bits(2) + 3;
      byte prev = dist_code_lens[dist_code_lens.size() - 1];
      for(byte c = 0; c < run; c++) {
        dist_code_lens.push_back(prev);
      }
    } else if (17 == symbol) {
      byte run = reader.read_bits(3) + 3;
      for (byte c = 0; c < run; c++) {
        dist_code_lens.push_back(0);
      }
    } else if (18 == symbol) {
      byte run = reader.read_bits(7) + 11;
      for (byte c = 0; c < run; c++) {
        dist_code_lens.push_back(0);
      }
    } else {
      assert(symbol <= 18);
    }
  }

  assert(dist_code_lens.size() == hdist);

  distance_codes = {dist_code_lens};
}
