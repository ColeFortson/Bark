/* Diffe-Hellman key exchange proof of concept by Grif Hughes - ghughes@smu.edu */

#include <gmp.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

static const char *prime = "16719638989018906513103022019443177741292783766058509585236442175152852400857057547800126886350046671452216300622593067838913809590756736851703111784112102869493543487024140270670735858753979111876731919875193357923727204127745393443504889829116838519273494671815743879708960480496628050302412483931054616240092747168301885301554687438693762103196901746216460422454153332018208854631330087200986944972994993317536616766835420809664841539967167149695266123101832929829861067792191714903262435494067436002975269646302045277813409669956280454260074037329111382714705016043320742439363098276805628405612911960431265324883";

int 
main(void)
{
        /* seed */
        srand(time(NULL));
        
        /* two secret values */
        unsigned int as = abs(rand() % 24000);
        unsigned int bs = abs(rand() % 24000);

        /* init contexts */
        mpz_t P, G, a, b, A, B, gen_one, gen_two;
        mpz_init(P); mpz_init(G); 
        mpz_init(a); mpz_init(b);
        mpz_init(A); mpz_init(B);
        mpz_init(gen_one); mpz_init(gen_two);
        
        mpz_set_str(P, prime, 10);
        mpz_set_ui(G, 2);
        mpz_set_ui(a, as);
        mpz_set_ui(b, bs);

        /* compute A and B */
        mpz_powm_sec(A, G, a, P);
        mpz_powm_sec(B, G, b, P);

        /* compute shared secret */
        mpz_powm_sec(gen_one, A, b, P);
        mpz_powm_sec(gen_two, B, a, P);

        /* validate */
        if(mpz_cmp(gen_one, gen_two) == 0)
                gmp_printf("secret key = %Zd\n", gen_one);
}
