//
// Created by trist on 24/03/2025.
//

#ifndef ASCON_H
#define ASCON_H

#include <stddef.h>
#include <stdint.h>

#define ROR64(x, n) ((x >> n) | (x << (64 - n)))

void ASCON_128_encrypt(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag);

void ASCON_128_decrypt(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag);

void ASCON_128a_encrypt(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag);

void ASCON_128a_decrypt(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag);

void ASCON_128_encrypt_custom(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag);

void ASCON_128_decrypt_custom(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag);

void ASCON_128a_encrypt_custom(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag);

void ASCON_128a_decrypt_custom(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag);

#endif //ASCON_H
