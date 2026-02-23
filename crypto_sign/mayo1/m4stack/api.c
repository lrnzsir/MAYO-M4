#include <api.h>
#include <mayo.h>

int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    return mayo_keypair(pk, sk);
}

int crypto_sign(unsigned char *sm, size_t *smlen, 
                const unsigned char *m, size_t mlen, 
                const unsigned char *sk) {
    return mayo_sign(sm, smlen, m, mlen, sk);
}

int crypto_sign_open(unsigned char *m, size_t *mlen, 
                     const unsigned char *sm, size_t smlen, 
                     const unsigned char *pk) {
    return mayo_open(m, mlen, sm, smlen, pk);
}
