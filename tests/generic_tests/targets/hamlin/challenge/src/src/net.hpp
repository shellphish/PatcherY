#pragma once

#include <iostream>

class Net {
public:
  Net(uint16_t p);

  std::istream* get_in();
  std::ostream* get_out();

  uint16_t port;
  int client_fd;
};
