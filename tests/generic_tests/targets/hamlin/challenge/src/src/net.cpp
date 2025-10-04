#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdlib>
#include <iostream>

#include "assert.hpp"
#include "log.hpp"
#include "hton.hpp"
#include "net.hpp"

Net::Net(uint16_t p) : port(p) {
  lll("preparing to listen on port %d", port);
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  int opt = 1;
  int sock_got = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                            &opt, sizeof(opt));
  assert_zero(sock_got);

  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = hton(port);

  int bind_got = bind(sock, (const struct sockaddr*)&address, sizeof(address));
  assert_zero(bind_got);

  int listen_got = listen(sock, 1);
  assert_zero(listen_got);

  struct sockaddr client_address;
  socklen_t client_address_len = sizeof(client_address);

  client_fd = accept(sock, &client_address, &client_address_len);
}

std::istream* Net::get_in() {
  return &std::cin;
}

std::ostream* Net::get_out() {
  return &std::cout;
}
