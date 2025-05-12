#ifndef A22AC708_4D34_4C8A_BF18_17748638D6F8
#define A22AC708_4D34_4C8A_BF18_17748638D6F8

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CRC32_POLYNOMIAL 0xEDB88320

static uint32_t crc32_table[256];

uint32_t crc32(const uint8_t *data, size_t length);

static void crc32_init_table()
{
    static bool has_run = false;

    if (has_run)
    {
        return;
    }

    has_run = true;
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; j++)
        {
            crc = (crc >> 1) ^ (CRC32_POLYNOMIAL * (crc & 1));
        }
        crc32_table[i] = crc;
    }
}

uint32_t crc32(const uint8_t *data, size_t length)
{
    crc32_init_table();
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < length; i++)
    {
        uint8_t byte = data[i];
        crc = (crc >> 8) ^ crc32_table[(crc ^ byte) & 0xFF];
    }

    return crc ^ 0xFFFFFFFF;
}

#endif /* A22AC708_4D34_4C8A_BF18_17748638D6F8 */
