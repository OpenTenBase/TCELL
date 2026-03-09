#ifndef  CRYPTO_FUNC_H
#define  CRYPTO_FUNC_H
#define DIGEST_SIZE 32

int digest_to_uuid(BYTE *digest,char *uuid);
int uuid_to_digest(char * uuid,BYTE *digest);
//int comp_proc_uuid(BYTE * dev_uuid,char * proc_name,BYTE * conn_uuid);
int calculate_context_sm3(char* context, int context_size, UINT32 *SM3_hash);

typedef struct
{
  UINT32 total_bytes_High;
  UINT32 total_bytes_Low;
  UINT32 vector[8];
  BYTE  buffer[64];     /* 64 byte buffer                            */

  BYTE ipad[64];       // HMAC: inner padding
  BYTE opad[64];       // HMAC: outer padding	
} sm3_context;

int SM3_init(sm3_context *index);
int SM3_update(sm3_context *index, BYTE *chunk_data, UINT32 chunk_length);
int SM3_final(sm3_context *index, UINT32 *SM3_hash);
void SM3_hmac(BYTE * key,int keylen, BYTE * input, int ilen,UINT32 * output);

#endif
