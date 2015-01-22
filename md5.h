#ifndef MD5_H
#define MD5_H

#include <stdint.h>

void md5_calc(const uint8_t *src, uint32_t len, uint8_t *enc);

#endif
