#include <iostream>
#include <vector>

#include "assert.hpp"
#include "log.hpp"

#include "inflate.hpp"
#include "deflate/block_type.hpp"
#include "deflate/code.hpp"
#include "deflate/destination.hpp"
#include "deflate/distance_destination.hpp"
#include "deflate/dynamic_code.hpp"
#include "deflate/fixed_code.hpp"
#include "deflate/fixed_distance_code.hpp"
#include "deflate/history.hpp"

using namespace deflate;

Inflate::Inflate(ZlibHeader zlh, BitVector& b) :
  header(zlh), compressed(b) {
  if (MAX_HISTORY == header.window_size()) {
    history = new ArrayHistory(header);
  } else {
    history = new VectorHistory(header);
  }
}

std::vector<byte> Inflate::inflated() {
  if (_inflated.size() > 0) return _inflated;

  inflate();

  assert(_inflated.size() > 0);

  return _inflated;
}

void Inflate::inflate() {
  byte is_final = 0;

  while (1 != is_final) {

    is_final = (byte)compressed.read_bits(1);
    BlockType blk_type = (BlockType)compressed.read_bits(2);

    lll("final %d block %s(%d)",
        is_final, to_string(blk_type).c_str(), (int)blk_type);

    switch(blk_type) {
    case BlockType::uncompressed:
      inflate_uncompressed();
      break;
    case BlockType::fixed:
      inflate_fixed();
      break;
    case BlockType::dynamic:
      inflate_dynamic();
      break;
    default:
      assert(false);
    }
  }
}

void Inflate::inflate_uncompressed() {
  compressed.finish_byte();
  uint16_t len = compressed.read_u16();
  uint16_t nlen = compressed.read_u16();
  assert(len == (~nlen & 0xffff));
  std::vector got = compressed.read_bytes(len);
  _inflated.insert(_inflated.end(),
                   got.begin(), got.end());
}

void Inflate::inflate_dynamic() {
  DynamicCode dynamic_code = DynamicCode(compressed);
  DynamicDistanceCode dyn_dist_code = dynamic_code.get_distance_code();
  inflate_code(dynamic_code, dyn_dist_code);
}

void Inflate::inflate_fixed() {
  FixedCode fc{};
  FixedDistanceCode dist_code{};
  inflate_code(fc, dist_code);
}

void Inflate::inflate_code(Code& code, DistanceCode& dist_code) {
  CodeBits path{};

  while (true) {
    path = path + compressed.read_bit();

    const Destination& dest = code.get_destination(path);

    if (dest == destination::identity::incomplete) {
      continue;
    }

    if (dest == destination::identity::end_of_block) {
      break;
    }

    if (dest == destination::identity::invalid) {
      assert(false);
    }



    const destination::Literal* lit_dest =
      dynamic_cast<const destination::Literal*>(&dest);

    if (nullptr != lit_dest) {
      history->append(lit_dest->val);
      _inflated.push_back(lit_dest->val);

      path = CodeBits{};
      continue;
    }

    const destination::Backref* backref_dest =
      dynamic_cast<const destination::Backref*>(&dest);

    assert(nullptr != backref_dest);
    const destination::Backref& backref = *backref_dest;

    uint32_t extra_len = compressed.read_bits(backref.bits);
    uint32_t total_len = backref.min + extra_len;

    assert(total_len <= (2 << 15) - 1);


    DistanceDestination const* dist_dest = nullptr;

    CodeBits dist_path{};
    do {
      dist_path = dist_path + compressed.read_bit();
      dist_dest = &dist_code.get_destination(dist_path);

    } while (dist_dest->is_incomplete());
    assert(!dist_dest->is_invalid());

    uint32_t extra_dist = compressed.read_bits(dist_dest->extra);
    uint32_t total_dist = dist_dest->min + extra_dist;





    std::vector<byte> backref_contents = history->copy(total_dist,
                                                       (uint16_t)total_len);
    assert(backref_contents.size() == total_len);
    _inflated.insert(_inflated.end(),
                     backref_contents.begin(),
                     backref_contents.end());

    path = CodeBits{};
  }
}
