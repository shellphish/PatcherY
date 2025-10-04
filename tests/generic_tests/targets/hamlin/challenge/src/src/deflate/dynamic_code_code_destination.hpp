#pragma once

#include "common.hpp"

namespace deflate {
  namespace dynamic_code_code {
    class DCCDestination {
    public:
      uint16_t literal;
      uint16_t length;
