#pragma once

#include <vector>

#include "history.hpp"

namespace deflate {
  class VectorHistory : public History {
  public:
    VectorHistory(ZlibHeader& zlh);
    virtual ~VectorHistory() override {};

    virtual void append(byte b) override;
    virtual std::vector<byte> copy(uint32_t dist, uint16_t count) override;

  private:
    ZlibHeader& header;
    std::vector<byte> buf;
    std::size_t cursor = 0;
  };
}
