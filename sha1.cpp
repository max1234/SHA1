#include "sha1.h"

SHA1::SHA1()
{
    Init() ;
}

void SHA1::SHA1Transform(__UINT32_TYPE__ state[5], __UINT8_TYPE__ block[64])
{
    __UINT32_TYPE__ a = state[0], b = state[1], c = state[2], d = state[3], e = state[4], temp, x[80];
    Decode (x, block, 64);

    for(int i = 16; i < 80; i++)
    {
        {
            x[i] = x[i - 3] ^ x[i - 8] ^ x[i - 14] ^ x[i - 16];
            x[i] = ROTATE_LEFT(x[i],1);
        }
    }

    for(int i = 0; i < 80; i++)
    {
        if (i < 20)
        {
            temp = F(b,c,d) + K[0];
        }
        else if (i < 40)
        {
            temp = G(b,c,d) + K[1];
        }
        else if (i < 60)
        {
            temp = H(b,c,d) + K[2];
        }
        else
        {
            temp = I(b,c,d) + K[3];
        }

        temp += ROTATE_LEFT(a,5) + x[i] + e;
        e = d;
        d = c;
        c = ROTATE_LEFT(b,30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;

}

void SHA1::Update(__UINT8_TYPE__ *input, __UINT16_TYPE__ inputlength)
{
    __UINT16_TYPE__ i, index, partlength;

    index = (__UINT16_TYPE__)((context.count[0] >> 3) & 0x3F);

    if ((context.count[0] += ((__UINT32_TYPE__)inputlength << 3)) < ((__UINT32_TYPE__)inputlength << 3))
        context.count[1]++;
    context.count[1] += ((__UINT32_TYPE__)inputlength >> 29);

    partlength = 64 - index;

    if (inputlength >= partlength)
    {
        memcpy((unsigned short *) & context.buffer[index], (unsigned short *)input, partlength);
        SHA1Transform (context.state, context.buffer);

        for (i = partlength; i + 63 < inputlength; i += 64)
            SHA1Transform (context.state, &input[i]);
        index = 0;
    }
    else
        i = 0;

    memcpy((unsigned short *) & context.buffer[index], (unsigned short *)&input[i], inputlength - i);
}

void SHA1::Final()
{
    __UINT8_TYPE__ bits[8];
    __UINT16_TYPE__ index, padlength;

    Encode(bits, context.count, 8);
    __UINT8_TYPE__ buf;
    for(int i = 0; i < 4; i++)
    {
        buf = bits[i];
        bits[i] = bits[i + 4];
        bits[i + 4] = buf;
    }

    index = (__UINT16_TYPE__)((context.count[0] >> 3) & 0x3f);
    padlength = (index < 56) ? (56 - index) : (120 - index);
    Update(PADDING, padlength);


    Update(bits, 8);


    Encode(digestRaw, context.state, 20);

    for(int pos = 0; pos < 20; pos++)
        sprintf(digestChars + (pos * 2), "%02x", digestRaw[pos]);
}

char* SHA1::digestFile(char *filename)
{
    FILE *file;

    int length;
    __UINT8_TYPE__ buffer[1024] ;

    if( (file = fopen(filename, "rb")) == NULL)
        return "File can't be opened";
    else
    {
        while(length = fread(buffer, 1, 1024, file))
            Update(buffer, length);
        Final();

        fclose( file );
    }
    return digestChars;
}

void SHA1::Init()
{
    context.count[0] = context.count[1] = 0;
    context.state[0] = 0x67452301; //A0
    context.state[1] = 0xEFCDAB89; //B0
    context.state[2] = 0x98BADCFE; //C0
    context.state[3] = 0x10325476; //D0
    context.state[4] = 0xC3D2E1F0; //E0
}

void SHA1::Encode(__UINT8_TYPE__ *output, __UINT32_TYPE__ *input, __UINT16_TYPE__ length)
{
    for (int i = 0; i < length / 4; i++)
    {
        output[4 * i] = (__UINT8_TYPE__)((input[i] >> 24) & 0xFF);
        output[4 * i + 1] = (__UINT8_TYPE__)((input[i] >> 16) & 0xFF);
        output[4 * i + 2] = (__UINT8_TYPE__)((input[i] >> 8) & 0xFF);
        output[4 * i + 3] = (__UINT8_TYPE__)((input[i]) & 0xFF);
    }
}

void SHA1::Decode(__UINT32_TYPE__ *output, __UINT8_TYPE__ *input, __UINT16_TYPE__ length)
{
    for (int i = 0; i < length / 4; i++)
        output[i] = (((__UINT32_TYPE__)input[4 * i] << 24) )|\
                (((__UINT32_TYPE__)input[4 * i + 1]) << 16) |\
                (((__UINT32_TYPE__)input[4 * i + 2]) << 8) |\
                (((__UINT32_TYPE__)input[4 * i + 3]));
}
