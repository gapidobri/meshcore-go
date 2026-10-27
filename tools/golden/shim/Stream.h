// Minimal Arduino Stream shim for building MeshCore on a host.
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

class Stream {
public:
  virtual ~Stream() {}
  size_t print(char c) { return fputc(c, stdout) == EOF ? 0 : 1; }
  size_t print(const char* s) { return fputs(s, stdout) == EOF ? 0 : 1; }
  size_t println() { return print('\n'); }
  size_t readBytes(uint8_t* buf, size_t len) { (void)buf; (void)len; return 0; }
  size_t write(const uint8_t* buf, size_t len) { return fwrite(buf, 1, len, stdout); }
};
