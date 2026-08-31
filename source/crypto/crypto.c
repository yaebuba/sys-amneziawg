/*
 * The two helpers the vendored primitives expect from their host project.
 * Both are written to resist the compiler optimising them away, which is the
 * whole reason they exist as functions rather than memset/memcmp calls.
 */
#include "crypto.h"

void crypto_zero(void *dest, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)dest;
    while (len--) *p++ = 0;
}

/* Constant time: comparing key material with memcmp leaks where it differs. */
bool crypto_equal(const void *a, const void *b, size_t size)
{
    const uint8_t *x = (const uint8_t *)a, *y = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < size; i++) diff |= (uint8_t)(x[i] ^ y[i]);
    return diff == 0;
}
