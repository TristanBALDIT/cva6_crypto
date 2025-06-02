#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

const uint32_t Rcon[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

uint8_t sbox[256] = {};
uint8_t inv_sbox[256] = {};

void print_sbox(const char *label, uint8_t box[256]) {
    printf("%s:\n", label);
    for (int i = 0; i < 256; i++) {
        printf("%02X ", box[i]);
    }
    printf("\n");
}

void initialize_aes_sbox()
{
    uint8_t p = 1, q = 1;
    do {
        p = p ^ (p<<1) ^ (p & 0x80 ? 0x1B : 0);

        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;

        uint8_t xformed = q ^ RTOL8(q,1) ^ RTOL8(q,2) ^ RTOL8(q,3) ^ RTOL8(q,4);
        sbox[p] = xformed ^ 0x63;
    } while (p != 1);
    sbox[0] = 0x63;
    for (int i = 0; i < 256; i++) {
        inv_sbox[sbox[i]] = i;
    }
}

void sub_bytes(uint32_t state[4])
{
    uint8_t *s = (uint8_t*) state;
    for (int i = 0; i < 16; i++)
    {
        s[i] = sbox[s[i]];
    }
}

void shift_rows(uint32_t state[4])
{
    uint8_t *bytes = (uint8_t *) state;  // little endian les octets sont inversés ci dessous

    // Décalage de la deuxième ligne (décalage de 1 octet vers la gauche)
    uint8_t temp1 = bytes[2];
    bytes[2] = bytes[6];
    bytes[6] = bytes[10];
    bytes[10] = bytes[14];
    bytes[14] = temp1;

    // Décalage de la troisième ligne (décalage de 2 octets vers la gauche)
    uint8_t temp2 = bytes[1];
    uint8_t temp3 = bytes[5];
    bytes[1] = bytes[9];
    bytes[5] = bytes[13];
    bytes[9] = temp2;
    bytes[13] = temp3;

    // Décalage de la quatrième ligne (décalage de 3 octets vers la gauche)
    uint8_t temp4 = bytes[0];
    bytes[0] = bytes[12];
    bytes[12] = bytes[8];
    bytes[8] = bytes[4];
    bytes[4] = temp4;
}

void mixColumns(uint32_t state[4])
{
    uint8_t *s = (uint8_t*) state; //little endian w32 = b0 b1 b2 b3 -> b3 b2 b1 b0

    for (int i = 0; i < 4; i++)
    {
        uint8_t s0 = s[4*i+3], s1 = s[4*i + 2], s2 = s[4*i + 1], s3 = s[4*i];
        uint8_t x2s0 = xtime(s0), x2s1 = xtime(s1), x2s2 = xtime(s2), x2s3 = xtime(s3);

        s[4*i+3] = x2s0 ^ (x2s1 ^ s1) ^ s2 ^ s3;
        s[4*i+2] = s0 ^ x2s1 ^ (x2s2 ^ s2) ^ s3;
        s[4*i+1] = s0 ^ s1 ^ x2s2 ^ (x2s3 ^ s3);
        s[4*i] = (x2s0 ^ s0) ^ s1 ^ s2 ^ x2s3;
    }
}

void addRoundKey(uint32_t state[4], const uint32_t *round_key)
{

    for (int i = 0; i < 4; i++)
    {
        state[i] ^= round_key[i];
    }
}


void keyExpansion(const uint32_t key[4], uint32_t *expanded_key, KeySize key_size)
{
    for (int i = 0; i < key_size; i++)
    {
        expanded_key[i] = key[i];
    }
    for (int i = 4; i < (key_size+7)*4 ; i++)
    {
        uint32_t temp = expanded_key[i - 1];
        if (i % key_size == 0)
        {
            temp = ((sbox[temp >> 16 & 0xFF] << 24) | (sbox[temp >> 8 & 0xFF] << 16) |
        (sbox[temp & 0xFF] << 8) | (sbox[temp >> 24])) ^ Rcon[(i / 4) - 1];

        }

        expanded_key[i] = expanded_key[i - 4] ^ temp;
    }
}


void inv_shift_rows(uint32_t state[4]) {

    uint8_t *bytes = (uint8_t *) state;   //little endian

    // Ligne 2 : Décalage de 1 octet vers la droite
    uint8_t temp = bytes[14];
    bytes[14] = bytes[10];
    bytes[10] = bytes[6];
    bytes[6] = bytes[2];
    bytes[2] = temp;

    // Ligne 3 : Décalage de 2 octets vers la droite
    temp = bytes[9];
    bytes[9] = bytes[1];
    bytes[1] = temp;
    temp = bytes[13];
    bytes[13] = bytes[5];
    bytes[5] = temp;

    // Ligne 3 : Décalage de 3 octets vers la droite (equivalent 1 vers la gauche)
    temp = bytes[4];
    bytes[4] = bytes[8];
    bytes[8] = bytes[12];
    bytes[12] = bytes[0];
    bytes[0] = temp;
}

// 0 4 8 12  -> 4 8 12 0


void inv_sub_bytes(uint32_t state[4]) {
    uint8_t *s = (uint8_t*) state;
    for (int i = 0; i < 16; i++) {
        s[i] = inv_sbox[s[i]];
    }
}

void inv_mixColumns(uint32_t state[4]) {
    uint8_t *s = (uint8_t*) state;
    for (int i = 0; i < 4; i++) {
        uint8_t s0 = s[4*i + 3], s1 = s[4*i + 2], s2 = s[4*i + 1], s3 = s[4*i];

        uint8_t x2s0 = xtime(s0), x2s1 = xtime(s1), x2s2 = xtime(s2), x2s3 = xtime(s3);
        uint8_t x4s0 = xtime(x2s0), x4s1 = xtime(x2s1), x4s2 = xtime(x2s2), x4s3 = xtime(x2s3);
        uint8_t x8s0 = xtime(x4s0), x8s1 = xtime(x4s1), x8s2 = xtime(x4s2), x8s3 = xtime(x4s3);
        uint8_t x9s0 = x8s0 ^ s0, x9s1 = x8s1 ^ s1, x9s2 = x8s2 ^ s2, x9s3 = x8s3 ^ s3;
        uint8_t xBs0 = x9s0 ^ x2s0, xBs1 = x9s1 ^ x2s1, xBs2 = x9s2 ^ x2s2, xBs3 = x9s3 ^ x2s3;
        uint8_t xDs0 = x9s0 ^ x4s0, xDs1 = x9s1 ^ x4s1, xDs2 = x9s2 ^ x4s2, xDs3 = x9s3 ^ x4s3;
        uint8_t xEs0 = x8s0 ^ x4s0 ^ x2s0, xEs1 = x8s1 ^ x4s1 ^ x2s1, xEs2 = x8s2 ^ x4s2 ^ x2s2, xEs3 = x8s3 ^ x4s3 ^ x2s3;

        s[4*i + 3] = xEs0 ^ xBs1 ^ xDs2 ^ x9s3;
        s[4*i + 2] = x9s0 ^ xEs1 ^ xBs2 ^ xDs3;
        s[4*i + 1] = xDs0 ^ x9s1 ^ xEs2 ^ xBs3;
        s[4*i] = xBs0 ^ xDs1 ^ x9s2 ^ xEs3;
    }
}


void encryptBlock(uint32_t block[4], uint32_t *key, KeySize key_size)
{
    uint32_t expanded_key[(key_size+7)*4];
    keyExpansion(key, expanded_key, key_size);
    addRoundKey(block, expanded_key);

    for (int i = 1; i < (key_size+6) ; i++)
    {
        sub_bytes(block);
        shift_rows(block);
        mixColumns(block);
        addRoundKey(block, expanded_key + 4 * i);
    }

    sub_bytes(block);
    shift_rows(block);
    addRoundKey(block, expanded_key + (key_size+6)*4);
}

void decryptBlock(uint32_t block[4], uint32_t *key, KeySize key_size)
{
    uint32_t expanded_key[(key_size+7)*4];
    keyExpansion(key, expanded_key, key_size);

    addRoundKey(block, expanded_key + (key_size+6)*4);

    inv_shift_rows(block);
    inv_sub_bytes(block);
    addRoundKey(block, expanded_key + (key_size+5)*4);

    for(int i = 1; i <= (key_size+5) ; i++)
    {
        inv_mixColumns(block);
        inv_shift_rows(block);
        inv_sub_bytes(block);
        addRoundKey(block, expanded_key + (key_size+5 - i)*4);
    }
}


void aes_cbc_encrypt(uint32_t *data, int num_blocks, uint32_t *key, uint32_t *iv, KeySize key_size)
{
    for (int i = 0; i < 16; i++)
    {
        data[i] = data[i] ^ iv[i];
    }
    encryptBlock(data, key, key_size);

    for(int i = 1; i < num_blocks; i++)
    {
        for(int j = 0; j < 16; j++)
        {
            data[i*16 + j] = data[i*16 + j] ^ data[(i-1) * 16 + j];
        }
        encryptBlock(data+16*i, key, key_size);
    }
}
