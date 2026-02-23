// SPDX-License-Identifier: Apache-2.0

#ifndef MAYO_H
#define MAYO_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "params.h"

/**
 * Status codes
 */
#define MAYO_OK 0
#define MAYO_ERR 1

/**
 * Mayo keypair generation.
 *
 * The implementation corresponds to Mayo.compactKeyGen() in the Mayo spec.
 * The caller is responsible to allocate sufficient memory to hold pk and sk.
 *
 * @param[out] pk Mayo public key (allocated array of CPK_BYTES bytes)
 * @param[out] sk Mayo secret key (allocated array of CSK_BYTES bytes)
 * @return int status code
 */
#define mayo_keypair MAYO_NAMESPACE(keypair)
int mayo_keypair(uint8_t *pk, uint8_t *sk);

/**
 * MAYO signature generation.
 *
 * The implementation performs Mayo.expandSK() + Mayo.sign() in the Mayo spec.
 * Keys provided is a compacted secret keys.
 * The caller is responsible to allocate sufficient memory to hold sm.
 *
 * @param[out] sm Signature concatenated with message (allocated array of SIG_BYTES + mlen bytes)
 * @param[out] smlen Pointer to the length of sm
 * @param[in] m Message to be signed
 * @param[in] mlen Message length
 * @param[in] sk Compacted secret key
 * @return int status code
 */
#define mayo_sign MAYO_NAMESPACE(sign)
int mayo_sign(uint8_t *sm, size_t *smlen, 
              const uint8_t *m, size_t mlen, 
              const uint8_t *sk);

/**
 * Mayo open signature.
 *
 * The implementation performs Mayo.verify(). If the signature verification succeeded, the original message is stored in m.
 * Keys provided is a compact public key.
 * The caller is responsible to allocate sufficient memory to hold m.
 *
 * @param[out] m Message stored if verification succeeds (allocated array of smlen - SIG_BYTES bytes)
 * @param[out] mlen Pointer to the length of m
 * @param[in] sm Signature concatenated with message
 * @param[in] smlen Length of sm
 * @param[in] pk Compacted public key
 * @return int status code
 */
#define mayo_open MAYO_NAMESPACE(open)
int mayo_open(uint8_t *m, size_t *mlen,
              const uint8_t *sm, size_t smlen,
              const uint8_t *pk);

/**
 * Mayo expand public key.
 *
 * The implementation corresponds to Mayo.expandPK() in the Mayo spec.
 * The caller is responsible to allocate sufficient memory to hold epk.
 *
 * @param[out] epk Expanded public key (allocated array of EPK_BYTES bytes)
 * @param[in] cpk Compacted public key
 * @return int return code
 */
#define mayo_expand_pk MAYO_NAMESPACE(expand_pk)
int mayo_expand_pk(uint8_t *epk, const uint8_t *cpk);

/**
 * Mayo expand secret key.
 * 
 * The implementation corresponds to Mayo.expandSK() in the Mayo spec.
 * The caller is responsible to allocate sufficient memory to hold expanded_sk.
 *
 * @param[out] esk Expanded secret key (allocated array of ESK_BYTES bytes)
 * @param[in] csk Compacted secret key
 * @return int return code
 */
#define mayo_expand_sk MAYO_NAMESPACE(expand_sk)
int mayo_expand_sk(uint8_t *esk, const uint8_t *csk);

/**
 * Mayo verify signature.
 *
 * The implementation performs Mayo.verify(). If the signature verification succeeded, returns 0, otherwise 1.
 * Keys provided is a compact public key.
 *
 * @param[out] m Message stored if verification succeeds (allocated array of mlen bytes)
 * @param[out] mlen Pointer to the length of m
 * @param[in] sig Signature
 * @param[in] pk Compacted public key
 * @return int 0 if verification succeeded, 1 otherwise.
 */
#define mayo_verify MAYO_NAMESPACE(verify)
int mayo_verify(const uint8_t *m, size_t mlen, 
                const uint8_t *sig,
                const uint8_t *pk);

/**
 * Mayo keypair generation (internal function).
 *
 * The implementation performs Mayo.compactKeyGen() in the Mayo spec.
 * after the sampling of the randomness.
 * The caller is responsible to allocate sufficient memory to hold pk.
 * 
 * @param[out] pk Mayo public key (allocated array of CPK_BYTES bytes)
 * @param[in] seed_sk Seed for secret key generation (allocated array of SK_SEED_BYTES bytes)
 * @return int status code
 */
#define mayo_keypair_internal MAYO_NAMESPACE(keypair_internal)
int mayo_keypair_internal(uint8_t *pk, uint8_t *seed_sk);

/**
 * Mayo signature generation (internal function).
 *
 * The implementation performs Mayo.sign() in the Mayo spec.
 * after the sampling of the randomness rnd (aka R in the spec).
 * The caller is responsible to allocate sufficient memory to hold sig.
 * 
 * @param[out] sig Signature (allocated array of SIG_BYTES bytes)
 * @param[out] siglen Pointer to the length of sig
 * @param[in] m Message to be signed
 * @param[in] mlen Message length
 * @param[in] rnd Randomness for signing (allocated array of R_BYTES bytes)
 * @param[in] sk Compacted secret key
 * @return int status code
 */
#define mayo_sign_signature_internal MAYO_NAMESPACE(sign_signature_internal)
int mayo_sign_signature_internal(uint8_t *sig, size_t *siglen,
                                 const uint8_t *m, size_t mlen,
                                 const uint8_t rnd[R_BYTES],
                                 const uint8_t *sk);

/**
 * Mayo signature generation.
 * 
 * The implementation performs Mayo.sign() in the Mayo spec.
 * In particular, the randomness for signing is generated and
 * then passed to the internal signing function mayo_sign_signature_internal.
 * The caller is responsible to allocate sufficient memory to hold sig.
 * 
 * @param[out] sig Signature (allocated array of SIG_BYTES bytes)
 * @param[out] siglen Pointer to the length of sig
 * @param[in] m Message to be signed
 * @param[in] mlen Message length
 * @param[in] sk Compacted secret key
 * @return int status code
 */
#define mayo_sign_signature MAYO_NAMESPACE(sign_signature)
int mayo_sign_signature(uint8_t *sig, size_t *siglen,
                        const uint8_t *m, size_t mlen,
                        const uint8_t *sk);

#endif  // MAYO_H
