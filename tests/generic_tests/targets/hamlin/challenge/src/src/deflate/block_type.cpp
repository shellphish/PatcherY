#include "block_type.hpp"

using namespace deflate;

std::ostream& operator<<(std::ostream& os, deflate::BlockType b) {
  return os << to_string(b);
}
std::string to_string(deflate::BlockType b) {
  switch (b) {
  case BlockType::uncompressed:
    return "uncompressed";
  case BlockType::fixed:
    return "fixed";
  case BlockType::dynamic:
    return "dynamic";
  case BlockType::_reserved:
    return "reserved (error)";
  }
}
