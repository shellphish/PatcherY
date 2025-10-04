#include "destination.hpp"

using namespace deflate::destination;

bool Base::operator==(const destination::Base& other) const {
  assert(false);
}

void Base::inspect(std::ostream& out) const {
  out << "destination::Base" << std::endl;
}

bool Base::operator!=(const destination::Base& other) const {
  return !(operator==(other));
}

bool Incomplete::operator==(const destination::Base& other) const {
  const Incomplete* other_ptr = dynamic_cast<const Incomplete*>(&other);
  if (nullptr == other_ptr) return false;

  return true;
}

void Incomplete::inspect(std::ostream& out) const {
  out << "destination::Incomplete" << std::endl;
}

bool Invalid::operator==(const destination::Base& other) const {
  const Invalid* other_ptr = dynamic_cast<const Invalid*>(&other);
  if (nullptr == other_ptr) return false;

  return true;
}

void Invalid::inspect(std::ostream& out) const {
  out << "destination::Invalid" << std::endl;
}

bool Literal::operator==(const destination::Base& other) const {
  const Literal* other_ptr = dynamic_cast<const Literal*>(&other);
  if (nullptr == other_ptr) return false;

  if (val != other_ptr->val) return false;

  return true;
}

void Literal::inspect(std::ostream& out) const {
  out << "destination::Literal val(" << (int)val << ")" << std::endl;
}

bool EndOfBlock::operator==(const destination::Base& other) const {
  const EndOfBlock* other_ptr = dynamic_cast<const EndOfBlock*>(&other);
  if (nullptr == other_ptr) return false;

  return true;
}

void EndOfBlock::inspect(std::ostream& out) const {
  out << "destination::EndOfBlock" << std::endl;
}

bool Backref::operator==(const destination::Base& other) const {
  const Backref* other_ptr = dynamic_cast<const Backref*>(&other);
  if (nullptr == other_ptr) return false;
  if (bits != other_ptr->bits) return false;
  if (min != other_ptr->min) return false;

  return true;
}

void Backref::inspect(std::ostream& out) const {
  out << "destination::Backref bits(" << std::hex << (int)bits <<
    ") min(" << std::dec << min << ")" << std::endl;
}

uint16_t Backref::len(BitVector bv) {
  if (0 == bits) return min;
  uint32_t lsb = bv.read_bits(bits);
  return min + lsb;
}
