/* Diffe-Hellman key exchange proof of concept by Grif Hughes - ghughes@smu.edu */

#include "engine.h"
#include <stdio.h>

int 
main(void)
{
        /* simulate two users */
        struct diffe_ctx *user1, *user2;

        /* each user has different cipher context */
        struct cipher_ctx *cctx1, *cctx2;
        init_diffe_ctx(&user1); init_diffe_ctx(&user2);

        /* each user computes shared secret to generate their key 
         * in client/server, each user would exchange their A values
         * */
        gen_shared_secret(&user1, user2->A);
        gen_shared_secret(&user2, user1->A);
        init_cipher_ctx(&cctx1, user1);
        init_cipher_ctx(&cctx2, user2);

        /* test data */
        char *buf = NULL;
        size_t len = 0;
        getline(&buf, &len, stdin);
        uint8_t *pt = gen_payload(buf, len);
        printf("plaintext: %s", buf);

        /* encrypt with user1's context */
        gcry_error_t err = encrypt(&cctx1, pt, len);
        if(err) {
                printf("%s\n", gcry_strsource(err));
                exit(err);
        }

        printf("ciphertext: ");
        for(int i = BLK_LEN; i < len; ++i)
                printf("%02x", pt[i]);

        /* decrypt with user2's context (tests that both independently
         * generated keys are equal */
        err = decrypt(&cctx2, pt, len);
        if(err) {
                printf("%s\n", gcry_strsource(err));
                exit(err);
        }
        printf("\ndecrypted: %s", pt + BLK_LEN); 

        /* cleanup */
        dest_diffe_ctx(&user1);
        dest_diffe_ctx(&user2);
        dest_cipher_ctx(&cctx1);
        dest_cipher_ctx(&cctx2);
        free(pt);
}
