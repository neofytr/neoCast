#ifndef BDD6A775_13FA_4499_B10E_7B1739B6D587
#define BDD6A775_13FA_4499_B10E_7B1739B6D587

#include <stdint.h>
#include <stddef.h>

#define XXH_PRIME32_1 0x9E3779B1U
#define XXH_PRIME32_2 0x85EBCA77U
#define XXH_PRIME32_3 0xC2B2AE3DU
#define XXH_PRIME32_4 0x27D4EB2FU
#define XXH_PRIME32_5 0x165667B1U

static inline uint32_t xxh_rotl32(uint32_t x, int r)
{
    return (x << r) | (x >> (32 - r));
}

uint32_t xxh32(const void *input, size_t length, uint32_t seed)
{
    const uint8_t *p = (const uint8_t *)input;
    const uint8_t *end = p + length;
    uint32_t h32;

    if (length >= 16)
    {
        const uint8_t *limit = end - 16;
        uint32_t v1 = seed + XXH_PRIME32_1 + XXH_PRIME32_2;
        uint32_t v2 = seed + XXH_PRIME32_2;
        uint32_t v3 = seed;
        uint32_t v4 = seed - XXH_PRIME32_1;

        while (p <= limit)
        {
            v1 += (*(const uint32_t *)p) * XXH_PRIME32_2;
            v1 = xxh_rotl32(v1, 13);
            v1 *= XXH_PRIME32_1;
            p += 4;

            v2 += (*(const uint32_t *)p) * XXH_PRIME32_2;
            v2 = xxh_rotl32(v2, 13);
            v2 *= XXH_PRIME32_1;
            p += 4;

            v3 += (*(const uint32_t *)p) * XXH_PRIME32_2;
            v3 = xxh_rotl32(v3, 13);
            v3 *= XXH_PRIME32_1;
            p += 4;

            v4 += (*(const uint32_t *)p) * XXH_PRIME32_2;
            v4 = xxh_rotl32(v4, 13);
            v4 *= XXH_PRIME32_1;
            p += 4;
        }

        h32 = xxh_rotl32(v1, 1) + xxh_rotl32(v2, 7) + xxh_rotl32(v3, 12) + xxh_rotl32(v4, 18);
    }
    else
    {
        h32 = seed + XXH_PRIME32_5;
    }

    h32 += (uint32_t)length;

    while (p + 4 <= end)
    {
        h32 += (*(const uint32_t *)p) * XXH_PRIME32_3;
        h32 = xxh_rotl32(h32, 17) * XXH_PRIME32_4;
        p += 4;
    }

    while (p < end)
    {
        h32 += (*p) * XXH_PRIME32_5;
        h32 = xxh_rotl32(h32, 11) * XXH_PRIME32_1;
        p++;
    }

    h32 ^= h32 >> 15;
    h32 *= XXH_PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= XXH_PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

#endif /* BDD6A775_13FA_4499_B10E_7B1739B6D587 */
