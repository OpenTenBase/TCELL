#include "data_type.h"
#include "crypto_func.h"

#ifndef _SM3_
#define _SM3_


int SM3(unsigned char *msg, unsigned int msglen, unsigned int *digest);

typedef struct
{
  UINT32 total_bytes_High;
  UINT32 total_bytes_Low;
  UINT32 vector[8];
  BYTE  buffer[64];     // 64 byte buffer

  BYTE ipad[64];       // HMAC: inner padding
  BYTE opad[64];       // HMAC: outer padding	
  
} SM3_context;


#define rol(x,n) ( ((n) % 32 == 0) ? (x) : ( ((x) << ((n) % 32)) | ((x) >> (32 - ((n) % 32))) ) )
#define P0(x) ((x^(rol(x,9))^(rol(x,17))))
#define P1(x) ((x^(rol(x,15))^(rol(x,23))))

#define CONCAT_4_BYTES( w32, w8, w8_i)            \
{                                                 \
    (w32) = ( (UINT32) (w8)[(w8_i)    ] << 24 ) |  \
            ( (UINT32) (w8)[(w8_i) + 1] << 16 ) |  \
            ( (UINT32) (w8)[(w8_i) + 2] <<  8 ) |  \
            ( (UINT32) (w8)[(w8_i) + 3]       );   \
}

#define SPLIT_INTO_4_BYTES( w32, w8, w8_i)        \
{                                                 \
    (w8)[(w8_i)] = (BYTE) ( (w32) >> 24 );    \
    (w8)[(w8_i) + 1] = (BYTE) ( (w32) >> 16 );    \
    (w8)[(w8_i) + 2] = (BYTE) ( (w32) >>  8 );    \
    (w8)[(w8_i) + 3] = (BYTE) ( (w32)       );    \
}

static BYTE SM3_padding[64] =
{
 (BYTE) 0x80, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0,
 (BYTE)    0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0,
 (BYTE)    0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0,
 (BYTE)    0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0, (BYTE) 0
};

#endif
