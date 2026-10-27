// Minimal Arduino shim for building MeshCore on a host.
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "Stream.h"

static inline char* ltoa(long value, char* buf, int radix) {
  (void)radix;  // only base 10 is used by MeshCore
  snprintf(buf, 24, "%ld", value);
  return buf;
}
