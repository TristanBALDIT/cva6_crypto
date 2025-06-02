//
// Created by trist on 17/03/2025.
//

#ifndef AES_H
#define AES_H

#include <stdint.h>

#define RTOL8(x,shift) ((uint8_t) ((x) << (shift)) | ((x) >> (8 - (shift))))
#define ROL32(x,n) ((x << n) | (x >> (32 - n)))
#define ROR32(x,n) ((x >> n) | (x << (32 - n)))
#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x1B))

typedef enum {
    KEY_SIZE_128 = 4,
    KEY_SIZE_192 = 6,
    KEY_SIZE_256 = 8
} KeySize;

extern const uint32_t Rcon[10];
extern uint8_t sbox[256];
extern uint8_t inv_sbox[256];

void initialize_aes_sbox();
void sub_bytes(uint32_t state[4]);
void shift_rows(uint32_t state[4]);
void mixColumns(uint32_t state[4]);
void addRoundKey(uint32_t state[4], const uint32_t round_key[4]);
void inv_shift_rows(uint32_t state[4]);
void inv_sub_bytes(uint32_t state[4]);
void inv_mixColumns(uint32_t state[4]);
void keyExpansion(const uint32_t key[4], uint32_t *expanded_key, KeySize key_size);
void encryptBlock(uint32_t block[4], uint32_t *key, KeySize key_size);
void decryptBlock(uint32_t block[4], uint32_t *key, KeySize key_size);

#endif // AES_H
