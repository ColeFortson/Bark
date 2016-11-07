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

void 
encrypt(struct cipher_ctx **cctx, uint8_t *buf, size_t len)
{
        (*cctx)->err = gcry_cipher_encrypt((*cctx)->hd, buf, len, NULL, 0);
        if((*cctx)->err) {
                printf("error: %s\n", gcry_strsource((*cctx)->err));
                exit((*cctx)->err);
        }
}

void
decrypt(struct cipher_ctx **cctx, uint8_t *buf, size_t len)
{
        (*cctx)->err = gcry_cipher_decrypt((*cctx)->hd, buf, len, NULL, 0);
        if((*cctx)->err) {
                printf("error: %s\n", gcry_strsource((*cctx)->err));
                exit((*cctx)->err);
        }
}

void
dest_cipher_ctx(struct cipher_ctx **in)
{
        gcry_cipher_close((*in)->hd);
}

#endif
