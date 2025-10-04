#include <cstdlib>
#include <iostream>

#include "assert.hpp"

void __assert_fail(const char* assertion,
                 const char* file,
                 unsigned int line,
                 const char* function) {
  std::cerr << std::dec << file << ":" << line << ": " << function <<
    ": Assertion `" << assertion << "` failed." << std::endl;

  std::exit(-1);
}

void __assert_zero_fail(const char* assertion,
                 const char* file,
                 unsigned int line,
                 const char* function) {
  std::cerr << file << ":" << line << ": " << function <<
    ": Non-zero assertion `" << assertion << "` failed." << std::endl;

  std::exit(-1);
}
