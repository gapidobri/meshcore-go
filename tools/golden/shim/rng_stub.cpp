// rweather/Crypto's Ed25519.cpp references the global RNG for key
// generation, which the harness never uses.
#include <string.h>
#include <RNG.h>
RNGClass::RNGClass() {}
RNGClass::~RNGClass() {}
void RNGClass::rand(uint8_t* data, size_t len) { memset(data, 0, len); }
RNGClass RNG;
