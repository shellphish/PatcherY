#pragma once


#ifdef NO_LOG
#define lll(...) /* noop( __VA_ARGS__) */
#else
#include <string>

#define lll(...) logloglog(__FILE__, __LINE__, __extension__ __PRETTY_FUNCTION__, __VA_ARGS__)

void logloglog(const char* file,
               unsigned int line,
               const char* function,
               std::string message, ...);
#endif
