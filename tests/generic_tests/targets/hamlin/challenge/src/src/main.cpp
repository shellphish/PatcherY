#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <sstream>

#include "assert.hpp"
#include "log.hpp"
#include "hrl.hpp"
#include "hton.hpp"
#include "metered_in.hpp"
#include "net.hpp"
#include "png.hpp"
#include "ppm.hpp"
#include "reader.hpp"

using std::string;

const uint32_t png_format = '\0PNG';
const uint32_t ppm_format = '\0PPM';
const uint32_t hrl_format = '\0HRL';

void expect_good(std::istream& in) {
  if (in.good()) return;

  if (in.eof()) {
    lll("got EOF, exiting");
    std::exit(0);
  }

  lll("expected in to be good, but it wasn't");
  std::exit(-1);
}

int main() {
  std::set_terminate([](){
                       lll("Unhandled exception, terminating");
                       std::exit(-1);
                     });

    #ifndef NO_TESTBED
    char *b = getenv("CHESS");
    if ( b == NULL ) {
        std::cout << "[TESTBED] ENV variable check failed" << std::endl;
        exit(0);
    }
    #endif

  std::istream* in_p;
  std::ostream* out_p;

  if (std::getenv("PORT")) {
    Net handler{(uint16_t)std::atoi(std::getenv("PORT"))};
    in_p = handler.get_in();
    out_p = handler.get_out();
  } else {
    in_p = &std::cin;
    out_p = &std::cout;
  }

  std::istream& in = *in_p;
  std::ostream& out = *out_p;

  expect_good(in);

  while (true) {

    uint32_t in_format;
    in.read((char*)(void*) &in_format, sizeof(in_format));

    expect_good(in);


    uint32_t out_format;
    in.read((char*)(void*) &out_format, sizeof(out_format));

    expect_good(in);


    uint64_t in_len_net;
    in.read((char*)(void*) &in_len_net, sizeof(in_len_net));
    uint64_t in_len = ntoh(in_len_net);

    expect_good(in);

    lll("formats in(net %x host %x) out(net %x host %x)",
        in_format, ntoh(in_format), out_format, ntoh(out_format));
    lll("len %d", in_len);


    std::ios_base::iostate existing_exceptions = in.exceptions();
    in.exceptions(std::ios::eofbit | existing_exceptions);

    Image* in_image;
    switch (ntoh(in_format)) {
    case ppm_format:
      in_image = new Ppm(in);
      break;
    case hrl_format:
      in_image = new Hrl(in);
      break;

    case png_format:
      in_image = new Png(in);
      break;

   default:
      lll("unknown format %lx", ntoh(in_format));
      assert(false);
    }

    in.exceptions(existing_exceptions);


    Image* out_image;
    switch (ntoh(out_format)) {
    case ppm_format:
      out_image = new Ppm(*in_image);
      break;
    case hrl_format:
      out_image = new Hrl(*in_image);
      break;

    default:
      lll("unknown format %lx", ntoh(out_format));
      assert(false);
    }

    delete in_image;

    std::ostringstream out_buf;
    out_image->write(out_buf);

    delete out_image;


    std::string out_str = out_buf.str();
    uint64_t out_len_net = hton(out_str.size());
    out.write((char*)(void*) &out_len_net, sizeof(out_len_net));

    out.write(out_str.c_str(), out_str.size());
    out.flush();
  }

  return 0;
}
