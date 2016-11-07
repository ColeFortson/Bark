/* Diffe-Hellman key exchange proof of concept by Grif Hughes - ghughes@smu.edu */

#include "diffe.h"
#include <stdio.h>

int 
main(void)
{
        struct diffe_ctx *user1, *user2;
        init_diffe_ctx(&user1); init_diffe_ctx(&user2);
        gen_shared_secret(&user1, user2->A);
        gen_shared_secret(&user2, user1->A);

        /* test data */
        char *buf = NULL;
        size_t len = 0;
        getline(&buf, &len, stdin);
        buf[len] = '\0';

        uint8_t *pt = gen_payload(buf, len);
        printf("plaintext: %s", buf); 

        /* init cipher context */
        gcry_cipher_hd_t hd;
        gcry_error_t err;
        gcry_cipher_open(&hd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
        gcry_cipher_setkey(hd, user1->key, KEY_LEN);

        printf("enc\n");
        /* encrypt and decrypt */
        err = gcry_cipher_encrypt(hd, pt, len, NULL, 0);
        if(err) { 
                printf("ERROR");
                exit(err);
        }
        printf("finish\n");

        printf("ciphertext: ");
        for(int i = BLK_LEN; i < len; ++i)
                printf("%02x", pt[i]);

        err = gcry_cipher_decrypt(hd, pt, len, NULL, 0);
        if(err) { 
                printf("ERROR");
                exit(err);
        }
        printf("\ndecrypted: %s\n", pt + BLK_LEN);

        /* cleanup */
        gcry_cipher_close(hd);
        dest_diffe_ctx(&user1);
        dest_diffe_ctx(&user2);
        free(pt);
}
