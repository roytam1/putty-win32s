/*
 * Stub random-seed/PRNG functions for pageant, which provides its own
 * random_read() and noise_ultralight() in pageant.c.
 */

#include "putty.h"

void random_save_seed(void)
{
}

void random_destroy_seed(void)
{
}

uint64_t prng_reseed_time_ms(void)
{
    return 0;
}
