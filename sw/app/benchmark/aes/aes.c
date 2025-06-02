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
    for (int i = 0; i < 4; i++)
    {
        data[i] = data[i] ^ iv[i];
    }
    encryptBlock(data, key, key_size);

    for(int i = 1; i < num_blocks; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            data[i*4 + j] = data[i*4 + j] ^ data[(i-1) * 4 + j];
        }
        encryptBlock(data+4*i, key, key_size);
    }
}

void aes_cbc_decrypt(uint32_t *data, int num_blocks, uint32_t *key, uint32_t *iv, KeySize key_size)
{

    for (int i = num_blocks-1; i > 0 ; i--)
    {
        decryptBlock(data + 4 * i, key, key_size);
        for(int j = 0; j < 4; j++)
        {
            data[i*4 + j] = data[i*4 + j] ^ data[(i-1) * 4 + j];
        }
    }

    decryptBlock(data, key, key_size);
    for(int i = 0; i < 4; i++)
    {
        data[i] = data[i] ^ iv[i];
    }

}

void aes_ctr(uint32_t *data, int num_blocks, uint32_t *key, uint32_t *iv, KeySize key_size)
{
    uint32_t counter = 0;
    uint32_t state[4];

    for (int i = 0; i < num_blocks; i++)
    {
        state[0] = iv[0];
        state[1] = iv[1];
        state[2] = iv[0];
        state[3] = counter;

        encryptBlock(state, key, key_size);

        for(int j = 0; j < 4; j++)
        {
            data[i*4 + j] = data[i*4 + j] ^ state[j];
        }

        counter++;
    }
}

void aes_gcm(uint32_t *data, uint32_t* ad_data, int num_blocks, int num_blocks_ad, uint32_t *key, uint32_t *iv, KeySize key_size, uint32_t T[4])
{
    uint32_t counter = 1;
    uint32_t hashsubkey[4] = {0,0,0,0};

    uint32_t counterBlock[4];
    counterBlock[0] = iv[0];
    counterBlock[1] = iv[1];
    counterBlock[2] = iv[2];
    counterBlock[3] = counter;

    encryptBlock(hashsubkey, key, key_size);
    encryptBlock(counterBlock, key, key_size);

    uint32_t firstBlock[4];
    memcpy(firstBlock,counterBlock,4*sizeof(uint32_t));

    uint32_t X[4];
    ghash_AD(X,ad_data, num_blocks_ad,hashsubkey);

    for(int i = 0; i < num_blocks; i++)
    {
        counter++;
        counterBlock[0] = iv[0];
        counterBlock[1] = iv[1];
        counterBlock[2] = iv[2];
        counterBlock[3] = counter;

        encryptBlock(counterBlock, key, key_size);

        for(int j = 0; j < 4; j++)
        {
            data[i*4 + j] = data[i*4 + j] ^ counterBlock[j];
            X[j] ^= data[i*4 + j];
        }

        galois_mult(X,X,hashsubkey);

    }
    uint64_t len_A = num_blocks_ad * 128;
    uint64_t len_C = num_blocks * 128;
    uint32_t len_block[4]; // Bloc de 128 bits pour stocker len(A) || len(C)
    len_block[0] = (uint32_t)(len_A >> 32); // Bits 127 à 96 de len_A
    len_block[1] = (uint32_t)(len_A & 0xFFFFFFFF); // Bits 95 à 64 de len_A
    len_block[2] = (uint32_t)(len_C >> 32); // Bits 63 à 32 de len_C
    len_block[3] = (uint32_t)(len_C & 0xFFFFFFFF); // Bits 31 à 0 de len_C

    for (int i = 0; i < 4; i++)
    {
        X[i] ^= len_block[i];
    }
    galois_mult(X,X,hashsubkey);
    for (int i = 0; i < 4; i++)
    {
        T[i] = X[i] ^ len_block[i];
        T[i] ^= firstBlock[i];
    }

}


// Multiplication dans GF(2^128)
void galois_mult(uint32_t Z[4], const uint32_t X[4], const uint32_t Y[4]) {
    uint32_t V[4];
    memcpy(V, X, 16); // V <- X
    memset(Z, 0, 16); // Z <- 0

    for (int i = 0; i < 128; i++) {
        // Vérifier si le i-ème bit de Y est à 1
        int word_index = i / 32;
        int bit_index = 31 - i % 32;
        if (Y[word_index] & (1U << bit_index)) {
            Z[0] ^= V[0];
            Z[1] ^= V[1];
            Z[2] ^= V[2];
            Z[3] ^= V[3];
        }

        // Vérifier le bit de poids fort de V (V127)
        uint32_t carry = V[3] & 1U;

        // Décalage à droite de V
        V[3] = (V[3] >> 1) | (V[2] << 31);
        V[2] = (V[2] >> 1) | (V[1] << 31);
        V[1] = (V[1] >> 1) | (V[0] << 31);
        V[0] >>= 1;

        // Appliquer le polynôme de réduction si le bit de poids fort était 1
        if (carry) {
            V[0] ^= R;
        }
    }
}

// Fonction GHASH
void ghash_AD(uint32_t output[4], const uint32_t *input, int num_blocks, const uint32_t H[4]) {
    uint32_t Y[4] = {0, 0, 0, 0};  // Y_0 = 0

    // Traitement bloc par bloc (taille de 128 bits = 4 * 32 bits)
    for (int i = 0; i < num_blocks; i++) {
        // XOR du bloc en entrée avec l'état actuel
        Y[0] ^= input[i * 4 + 0];
        Y[1] ^= input[i * 4 + 1];
        Y[2] ^= input[i * 4 + 2];
        Y[3] ^= input[i * 4 + 3];

        // Multiplication dans GF(2^128)
        galois_mult(Y, Y, H);
    }

    // Stocker le résultat final
    output[0] = Y[0];
    output[1] = Y[1];
    output[2] = Y[2];
    output[3] = Y[3];
}
