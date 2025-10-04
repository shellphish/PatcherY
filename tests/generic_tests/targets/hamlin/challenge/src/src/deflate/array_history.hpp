#pragma once

#include <array>

#include "history.hpp"

namespace deflate {
  class ArrayHistory : public History {
  public:
    ArrayHistory(ZlibHeader& zlh);
    virtual ~ArrayHistory() override {};

    virtual void append(byte b) override;
    virtual std::vector<byte> copy(uint32_t dist, uint16_t count) override;

  private:
    ZlibHeader& header;
    std::array<byte, MAX_HISTORY> buf = {};
    std::size_t cursor = 0;
    bool wrapped = false;
  };
}
