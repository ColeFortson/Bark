/* Diffe-Hellman key exchange proof of concept by Grif Hughes - ghughes@smu.edu */

#include "diffe.h"
#include "engine.h"
#include <stdio.h>

int 
main(void)
{
        struct diffe_ctx *user1, *user2;
        struct cipher_ctx *cctx;
        init_diffe_ctx(&user1); init_diffe_ctx(&user2);

        gen_shared_secret(&user1, user2->A);
        gen_shared_secret(&user2, user1->A);
        init_cipher_ctx(&cctx, user1);

        /* test data */
        char *buf = NULL;
        size_t len = 0;
        getline(&buf, &len, stdin);
        uint8_t *pt = gen_payload(buf, len);
        printf("plaintext: %s", buf);

        encrypt(&cctx, pt, len);

        printf("ciphertext: ");
        for(int i = BLK_LEN; i < len; ++i)
                printf("%02x", pt[i]);

        decrypt(&cctx, pt, len);
        printf("%s", pt + BLK_LEN); 

        /* cleanup */
        dest_cipher_ctx(&cctx);
        dest_diffe_ctx(&user1);
        dest_diffe_ctx(&user2);
        free(pt);
}
