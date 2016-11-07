/* Diffe-Hellman key exchange proof of concept by Grif Hughes - ghughes@smu.edu */

#ifndef DIFFE_H
#define DIFFE_H

#include <gcrypt.h>
#include <gmp.h>
#include <inttypes.h>
#include <time.h>

static const char *prime = "16719638989018906513103022019443177741292783766058509585236442175152852400857057547800126886350046671452216300622593067838913809590756736851703111784112102869493543487024140270670735858753979111876731919875193357923727204127745393443504889829116838519273494671815743879708960480496628050302412483931054616240092747168301885301554687438693762103196901746216460422454153332018208854631330087200986944972994993317536616766835420809664841539967167149695266123101832929829861067792191714903262435494067436002975269646302045277813409669956280454260074037329111382714705016043320742439363098276805628405612911960431265324883";

#define GENERATOR       2
#define RANDOM_SIZEB    8 
#define BASE            10
#define BLK_LEN         (gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256))
#define KEY_LEN         (gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256))

struct keygen_ctx {
        mpz_t P, G;
        gmp_randstate_t state;
};

struct diffe_ctx {
        mpz_t A, sec;
        uint8_t *shared, *key;
        struct keygen_ctx *kctx;
};

void
init_keygen_ctx(struct keygen_ctx **kctx)
{
        *kctx = malloc(sizeof(struct keygen_ctx));
        mpz_init_set_str((*kctx)->P, prime, BASE);
        mpz_init_set_ui((*kctx)->G, GENERATOR);
        gmp_randinit_mt((*kctx)->state);
        gmp_randseed_ui((*kctx)->state, time(NULL));
}

void
init_diffe_ctx(struct diffe_ctx **dctx)
{
        *dctx = malloc(sizeof(struct diffe_ctx));
        mpz_init((*dctx)->A);
        (*dctx)->shared = NULL;
        (*dctx)->key = NULL;
        init_keygen_ctx(&((*dctx)->kctx));
        
        mpz_init_set_ui((*dctx)->sec, gmp_urandomb_ui((*dctx)->kctx->state, RANDOM_SIZEB * 8));
        mpz_powm_sec((*dctx)->A, (*dctx)->kctx->G, (*dctx)->sec, (*dctx)->kctx->P);
}

void
gen_shared_secret(struct diffe_ctx **my, mpz_t your_A)
{
        mpz_t tmp;
        mpz_init(tmp);
        mpz_powm_sec(tmp, your_A, (*my)->sec, (*my)->kctx->P);

        (*my)->shared = malloc(mpz_sizeinbase(tmp, BASE) + 2);        
        mpz_get_str((*my)->shared, BASE, tmp);

        (*my)->key = malloc(KEY_LEN);
        gcry_md_hash_buffer(GCRY_MD_SHA256, (*my)->key, (*my)->shared, 256);
}

void 
dest_keygen_ctx(struct keygen_ctx **in)
{
        mpz_clears((*in)->P, (*in)->G, NULL);
        gmp_randclear((*in)->state);
        free(*in);
}

void 
dest_diffe_ctx(struct diffe_ctx **in)
{
        free((*in)->key);
        free((*in)->shared);
        mpz_clears((*in)->A, (*in)->sec, NULL);
        dest_keygen_ctx(&((*in)->kctx));
        free(*in);
}

uint8_t  *
gen_payload(uint8_t  *buf, size_t len)
{
        uint8_t *tmp = calloc(len + BLK_LEN, 1);
        uint8_t iv[BLK_LEN];
        gcry_create_nonce(iv, BLK_LEN);
        strncpy(tmp, iv, BLK_LEN); 
        strncpy(tmp + BLK_LEN, buf, len);
        return tmp;
}

#endif
