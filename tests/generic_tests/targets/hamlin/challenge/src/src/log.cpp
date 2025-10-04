#ifndef NO_LOG
#include <cstdio>
#include <cstdarg>

#include "log.hpp"

void logloglog(const char* file,
               unsigned int line,
               const char* function,
               std::string message, ...) {
  fprintf(stderr, "%s:%d: %s: ", file, line, function);
  va_list args;
  va_start(args, message);
  vfprintf(stderr, message.c_str(), args);
  va_end(args);
  fprintf(stderr, "\n");
}
#endif
