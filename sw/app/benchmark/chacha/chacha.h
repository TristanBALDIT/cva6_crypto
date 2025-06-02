//
// Created by trist on 18/03/2025.
//

#ifndef CHACHA_H
#define CHACHA_H
#include <stdint.h>
#include <stddef.h>
#define CHACHA_CONST_0 0x61707865  // "expa"
#define CHACHA_CONST_1 0x3320646E  // "nd 3"
#define CHACHA_CONST_2 0x79622D32  // "2-by"
#define CHACHA_CONST_3 0x6B206574  // "te k"

#define ROTL32(v, n) ((v << n) | (v >> (32 - n)))

void QR(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d);
void KeyBlockGeneration(uint32_t block[16], uint32_t key[8], uint32_t nonce[3], uint32_t counter);
void Chacha20(uint32_t *data, uint32_t key[8], uint32_t nonce[3], size_t num_blocks);
void Chacha20_Poly1305(uint32_t *data, uint32_t *ad_data, uint32_t key[8], uint32_t nonce[3], size_t num_blocks, size_t num_ad_blocks, uint8_t mac[16]);

#endif //CHACHA_H
