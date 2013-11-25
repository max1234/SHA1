#ifndef SHA1_H
#define SHA1_H

#include <stdio.h>
#include <string.h>
#include <math.h>

static __UINT8_TYPE__ PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static __UINT32_TYPE__ K[4] = {0x5A827999,\
                            0x6ED9EBA1,\
                            0x8F1BBCDC,\
                            0xCA62C1D6};

#define F(x, y, z) (z ^ (x & (y ^ z)))
#define G(x, y, z) (x ^ y ^ z)
#define H(x, y, z) ((x & y) | (z & (x | y)))
#define I(x, y, z) (x ^ y ^ z)

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

class SHA1
{
public:

    SHA1();
    char* digestFile(char *filename);

private:

    struct __context_t {
      __UINT32_TYPE__ state[5];
      __UINT32_TYPE__ count[2]; //number of bits, mod 2^64
      __UINT8_TYPE__ buffer[64]; //input
    } context ;


    __UINT8_TYPE__ digestRaw[20];
    char digestChars[41];

    void SHA1Transform(__UINT32_TYPE__ state[5], __UINT8_TYPE__ block[64]);
    void Update(__UINT8_TYPE__ *input, __UINT16_TYPE__ inputLen);
    void Final();
    void Init();
    void Encode(__UINT8_TYPE__ *output, __UINT32_TYPE__ *input, __UINT16_TYPE__ len);
    void Decode(__UINT32_TYPE__ *output, __UINT8_TYPE__ *input, __UINT16_TYPE__ len);

};

#endif
