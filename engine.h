#ifndef ENGINE_H
#define ENGINE_H

#include "diffe.h"

struct cipher_ctx {
        gcry_cipher_hd_t hd;
        gcry_error_t err;
};

void
init_cipher_ctx(struct cipher_ctx **cctx, struct diffe_ctx *dctx)
{
        *cctx = malloc(sizeof(struct cipher_ctx));
        gcry_cipher_open(&((*cctx)->hd), GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
        gcry_cipher_setkey((*cctx)->hd, dctx->key, KEY_LEN);
}

gcry_error_t  
encrypt(struct cipher_ctx **cctx, uint8_t *buf, size_t len)
{
        (*cctx)->err = gcry_cipher_encrypt((*cctx)->hd, buf, len, NULL, 0);
        if((*cctx)->err) 
                return (*cctx)->err;
        return 0;
}

gcry_error_t
decrypt(struct cipher_ctx **cctx, uint8_t *buf, size_t len)
{
        (*cctx)->err = gcry_cipher_decrypt((*cctx)->hd, buf, len, NULL, 0);
        if((*cctx)->err) 
                return (*cctx)->err;
        return 0;
}

void
dest_cipher_ctx(struct cipher_ctx **cctx)
{
        gcry_cipher_close((*cctx)->hd);
}

#endif
