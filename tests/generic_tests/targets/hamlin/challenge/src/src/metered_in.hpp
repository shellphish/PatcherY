#pragma once

#include <cstdint>
#include <istream>

class MeteredIn : public std::istream {
public:
  MeteredIn(std::istream& base, uint64_t limit);

  MeteredIn& read(char* dest, std::streamsize count);

  char peek();
private:
  uint64_t remain;
};
