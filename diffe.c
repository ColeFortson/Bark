/* Diffe-Hellman key exchange proof of concept by Grif Hughes - ghughes@smu.edu */

#include <gmp.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <gcrypt.h>

static const char *prime = "16719638989018906513103022019443177741292783766058509585236442175152852400857057547800126886350046671452216300622593067838913809590756736851703111784112102869493543487024140270670735858753979111876731919875193357923727204127745393443504889829116838519273494671815743879708960480496628050302412483931054616240092747168301885301554687438693762103196901746216460422454153332018208854631330087200986944972994993317536616766835420809664841539967167149695266123101832929829861067792191714903262435494067436002975269646302045277813409669956280454260074037329111382714705016043320742439363098276805628405612911960431265324883";

#define D_LEN   (gcry_md_get_algo_dlen(GCRY_MD_SHA256))
#define BLK_LEN (gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256))
#define KEY_LEN (gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256))

int 
main(void)
{
        /* seed, test */
        srand(time(NULL));

        /* two secret values, test */
        unsigned int as = abs(rand());
        unsigned int bs = abs(rand());

        /* init values */
        mpz_t P, G, a, b, A, B, sec_a, sec_b;
        mpz_init_set_str(P, prime, 10);
        mpz_init_set_ui(G, 2);
        mpz_init_set_ui(a, as);
        mpz_init_set_ui(b, bs);
        mpz_init(A); mpz_init(B);
        mpz_init(sec_a); mpz_init(sec_b);

        /* compute A and B */
        mpz_powm_sec(A, G, a, P);
        mpz_powm_sec(B, G, b, P);

        /* compute shared secret */
        mpz_powm_sec(sec_a, A, b, P);
        mpz_powm_sec(sec_b, B, a, P);

        /* get buffer to be passed to KDF (SHA256) */
        uint8_t *out = malloc(mpz_sizeinbase(sec_a, 10) + 2);
        mpz_get_str(out, 10, sec_a);

        /* hash shared secret to get 256 bit key */ 
        uint8_t *key = malloc(D_LEN);
        gcry_md_hash_buffer(GCRY_MD_SHA256, key, out, 256);

        /* test data 63 (+ 1) bytes */
        uint8_t *t = malloc(64);
        strncpy(t, "a this is a test this is a testa this is a testa this is a test", 63);
        size_t len = strlen(t) + 1;
        printf("plaintext: %s\n", t);

        /* init cipher context */
        gcry_cipher_hd_t hd;
        gcry_error_t err;
        uint8_t *iv = malloc(BLK_LEN);

        gcry_create_nonce(iv, BLK_LEN);
        gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
        gcry_cipher_setkey(hd, key, KEY_LEN);
        gcry_cipher_setiv(hd, iv, BLK_LEN);

        /* encrypt and decrypt */
        err = gcry_cipher_encrypt(hd, t, len, NULL, 0);
        if(err) 
                printf("error %s\n", gcry_strsource(err));
        printf("ciphertext: ");
        for(int i = 0; i < len; ++i)
                printf("%02x", t[i]);
        puts("\n");

        err = gcry_cipher_decrypt(hd, t, len, NULL, 0);
        if(err)
                printf("error %s\n", gcry_strsource(err));
        printf("decrypted: %s\n", t);

        /* cleanup */
        gcry_cipher_close(hd);
        mpz_clears(P, G, a, b, A, B, sec_a, sec_b, NULL);
        free(out);
        free(key);
        free(t);
        free(iv);
}
