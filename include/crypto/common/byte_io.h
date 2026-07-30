#pragma once

/* Alignment-safe, host-endian load/store of fixed-width ints to byte buffers:
 * memcpy avoids the UB of an unaligned `*(uint32_t*)p`. */

#include <stdint.h>
#include <string.h>

static inline void store_u32(uint8_t *p, uint32_t v) { memcpy(p, &v, sizeof(v)); }
static inline uint32_t load_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, sizeof(v)); return v; }
