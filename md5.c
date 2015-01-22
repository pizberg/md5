/***************************************************************
**
** Copyright (C) 2015 inSMART Team. All rights reserved.
**
** @auth: pizberg
** @date: 2015-01-22
** @vers: 1.0.0
** @file: md5.c
**
***************************************************************/

#include "md5.h"
#include "string.h"

uint32_t state[4];   /* state (ABCD) */


/* floor((1ull << 32) * fabs(sin(i))) */
const uint32_t md5_T[4][16] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

const uint8_t md5_S[4][4] = {
        { 7, 12, 17, 22 },
        { 5,  9, 14, 20 },
        { 4, 11, 16, 23 },
        { 6, 10, 15, 21 },
};

/* coefficient of block X index */
const uint8_t  md5_X[4][2] = { { 0, 1 }, { 1, 5 }, { 5, 3 }, { 0, 7 } };





static void md5_init(void);
static void md5_transform(const void *x);


/* F, G, H, I are basic MD5 functions */
static uint32_t md5_F(uint32_t x, uint32_t y, uint32_t z) { return (((x) & (y)) | ((~x) & (z))); }
static uint32_t md5_G(uint32_t x, uint32_t y, uint32_t z) { return (((x) & (z)) | ((y) & (~z))); }
static uint32_t md5_H(uint32_t x, uint32_t y, uint32_t z) { return ((x) ^ (y) ^ (z)); }
static uint32_t md5_I(uint32_t x, uint32_t y, uint32_t z) { return ((y) ^ ((x) | (~z))); }
uint32_t(*FUNC[4])(uint32_t, uint32_t, uint32_t) = { md5_F, md5_G, md5_H, md5_I };

static uint32_t md5_rotl(uint32_t x, uint8_t n) { return (((x) << (n)) | ((x) >> (32 - (n)))); }
static uint8_t  md5_rotr(uint8_t  x, uint8_t n) { return (((x) >> (n)) | ((x) << ( 8 - (n)))); }

//#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32-(n))))
//#define ROTR8(x, n) (((x) >> (n)) | ((x) << (8-(n))))

/* a = b + ROTL((a + F(b, c, d) + X[k] + T[i]), s). */
//static uint32_t TRAN(uint8_t r, uint32_t *a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t t, uint8_t s) {
//    return (*a) = (b)+(ROTL32((*a)+(FUNC[r](b, c, d)) + (x) + (t), (s)));
//}
#define TRAN(r, a, b, c, d, x, t, s) (a) = (b) + (md5_rotl((a) + (FUNC[r]((b), (c), (d))) + (x) + (t), (s)))





/* transforms state based on block. */
void md5_transform(const void* x)
{
    uint32_t s[4];
    uint8_t  i, n, r;

    for (i = 0; i < 4; i++)
        s[i] = state[i];

    for (r = 0; r < 4; r++) /* round */
    {
        for (n = 0; n < 16; n++)
        {
            i = md5_rotr(27, n % 4 * 2); /* 27 = 00 01 10 11 (0 1 2 3) */
            TRAN(r, s[(i >> 6) & 3], s[(i >> 4) & 3], s[(i >> 2) & 3], s[i & 3], *((uint32_t*)x + (md5_X[r][0] + n * md5_X[r][1]) % 16), md5_T[r][n], md5_S[r][n % 4]);
        }
    }

    for (i = 0; i < 4; i++)
        state[i] += s[i];
}







/* n*512+448+64 = (n+1)*512 bits */
void md5_proc(const uint8_t* src, uint32_t len)
{
    union {
        uint8_t  v8[64];
        uint64_t v64[8];
    } buf;
    uint32_t rst = len; /* the rest length of the src */

    /* pre-blocks */
    while (rst >= 64)
    {
        md5_transform(src);
        src += 64;
        rst -= 64;
    }

    /* init 512 bits buffer */
    memset(buf.v8, 0, 64);
    memcpy(buf.v8, src, rst); /* rst < 64 */

    /* insert padding one */
    buf.v8[rst] = 0x80;

    /* insert length value */
    if (rst >= 56) /* must contain padding one */
    {
        md5_transform(buf.v8);
        memset(buf.v8, 0, 56);
    }

    /* insert src bit length at the last 8 bytes */
    buf.v64[7] = len * 8;

    /* last block */
    md5_transform(buf.v8);

    /* zeroize sensitive information */
    //memset(x, 0, 64);
}

/* initializes MD5 context */
void md5_init()
{
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
}


void md5_calc(const uint8_t *src, uint32_t len, uint8_t *enc)
{
    md5_init();
    md5_proc(src, len);

    memcpy(enc, state, 16); /* save as uint8 array */
}

