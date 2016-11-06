/* Diffe-Hellman key exchange proof of concept by Grif Hughes - ghughes@smu.edu */

#include <gcrypt.h>
#include <gmp.h>
#include <inttypes.h>
#include <stdio.h>

static const char *prime = "16719638989018906513103022019443177741292783766058509585236442175152852400857057547800126886350046671452216300622593067838913809590756736851703111784112102869493543487024140270670735858753979111876731919875193357923727204127745393443504889829116838519273494671815743879708960480496628050302412483931054616240092747168301885301554687438693762103196901746216460422454153332018208854631330087200986944972994993317536616766835420809664841539967167149695266123101832929829861067792191714903262435494067436002975269646302045277813409669956280454260074037329111382714705016043320742439363098276805628405612911960431265324883";

#define GENERATOR 2
#define RANDOM_SIZEB 8 
#define BLK_LEN (gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256))
#define KEY_LEN (gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256))

static inline uint8_t *
gen_payload(uint8_t *buf, size_t len)
{
        uint8_t *tmp = calloc(len + BLK_LEN, 1);
        uint8_t iv[BLK_LEN];
        gcry_create_nonce(iv, BLK_LEN);
        strncpy(tmp, iv, BLK_LEN); 
        strncpy(tmp + BLK_LEN, buf, len);
        return tmp;
}

int 
main(void)
{
        /* two secret values, test */
        uint8_t *as = malloc(RANDOM_SIZEB);
        uint8_t *bs = malloc(RANDOM_SIZEB);
        gcry_randomize(as, RANDOM_SIZEB, GCRY_STRONG_RANDOM);
        gcry_randomize(bs, RANDOM_SIZEB, GCRY_STRONG_RANDOM);

        /* init values */
        mpz_t P, G, a, b, A, B, sec_a, sec_b;
        mpz_init_set_str(P, prime, 10);
        mpz_init_set_ui(G, GENERATOR);
        mpz_init_set_str(a, as, 10);
        mpz_init_set_str(b, bs, 10);
        mpz_init(A); mpz_init(B);
        mpz_init(sec_a); mpz_init(sec_b);

        /* compute A and B, zero secret values */
        mpz_powm_sec(A, G, a, P);
        mpz_powm_sec(B, G, b, P);
        memset(as, 0, RANDOM_SIZEB); memset(bs, 0, RANDOM_SIZEB);
        free(as); free(bs);

        /* compute shared secret */
        mpz_powm_sec(sec_a, A, b, P);
        mpz_powm_sec(sec_b, B, a, P);

        /* get buffer to be passed to KDF (SHA256) */
        uint8_t *out = malloc(mpz_sizeinbase(sec_a, 10) + 2);
        mpz_get_str(out, 10, sec_a);

        /* hash shared secret to get 256 bit key */ 
        uint8_t *key = malloc(KEY_LEN);
        gcry_md_hash_buffer(GCRY_MD_SHA256, key, out, 256);

        /* test data */
        char *buf = NULL;
        size_t len = 0;
        getline(&buf, &len, stdin);

        uint8_t *pt = gen_payload(buf, len);
        printf("plaintext: %s\n", buf); 

        /* init cipher context */
        gcry_cipher_hd_t hd;
        gcry_error_t err;
        gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
        gcry_cipher_setkey(hd, key, KEY_LEN);

        /* encrypt and decrypt */
        err = gcry_cipher_encrypt(hd, pt, len, NULL, 0);
        if(err) 
                exit(err);
        printf("ciphertext: ");
        for(int i = BLK_LEN; i < len; ++i)
                printf("%02x", pt[i]);

        err = gcry_cipher_decrypt(hd, pt, len, NULL, 0);
        if(err)
                exit(err);
        printf("\ndecrypted: %s\n", pt + BLK_LEN);

        /* cleanup */
        gcry_cipher_close(hd);
        mpz_clears(P, G, a, b, A, B, sec_a, sec_b, NULL);
        free(out);
        free(key);
        free(pt);
}
