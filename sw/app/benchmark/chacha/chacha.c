//
// Created by trist on 18/03/2025.
//

#include "chacha.h"

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include "poly1305.h"

void QR(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b; *d ^= *a; *d = ROTL32(*d, 16);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 12);
    *a += *b; *d ^= *a; *d = ROTL32(*d, 8);
    *c += *d; *b ^= *c; *b = ROTL32(*b, 7);

}

void KeyBlockGeneration(uint32_t block[16], uint32_t key[8], uint32_t nonce[3], uint32_t counter)
{
    block[0] = CHACHA_CONST_0;
    block[1] = CHACHA_CONST_1;
    block[2] = CHACHA_CONST_2;
    block[3] = CHACHA_CONST_3;

    memcpy(&block[4], key, 8 * sizeof(uint32_t));
    block[12] = counter;
    memcpy(&block[13], nonce, 3 * sizeof(uint32_t));

    // for (int i = 0; i < 16; i++)
    // {
    //     if (i % 4 == 0)
    //     {
    //         printf("\n");
    //     }
    //     printf("%08X ", block[i]);
    // }
    // printf("\n");

    uint32_t working_block[16];
    memcpy(working_block, block, 16*sizeof(uint32_t));

    for (int i = 0; i < 10; i++) { // 10 double rounds = 20 rounds
        // Column rounds
        QR(&working_block[0], &working_block[4], &working_block[8], &working_block[12]);
        QR(&working_block[1], &working_block[5], &working_block[9], &working_block[13]);
        QR(&working_block[2], &working_block[6], &working_block[10], &working_block[14]);
        QR(&working_block[3], &working_block[7], &working_block[11], &working_block[15]);

        // Diagonal rounds
        QR(&working_block[0], &working_block[5], &working_block[10], &working_block[15]);
        QR(&working_block[1], &working_block[6], &working_block[11], &working_block[12]);
        QR(&working_block[2], &working_block[7], &working_block[8], &working_block[13]);
        QR(&working_block[3], &working_block[4], &working_block[9], &working_block[14]);
    }

    // for (int i = 0; i < 16; i++)
    // {
    //     if (i % 4 == 0)
    //     {
    //         printf("\n");
    //     }
    //     printf("%08X ", working_block[i]);
    // }
    // printf("\n");

    for (int i = 0; i < 16; i++) block[i] += working_block[i];
}


void Chacha20(uint32_t *data, uint32_t key[8], uint32_t nonce[3], size_t num_blocks)
{
    uint32_t counter = 1;
    for (int i = 0; i < num_blocks; i++)
    {
        uint32_t key_block[16];
        KeyBlockGeneration(key_block, key, nonce, counter);
        for (int j = 0; j < 16; j++)
        {
            data[16*i+j] ^= key_block[j];
        }
        counter++;
    }
}


void Chacha20_Poly1305(uint32_t *data, uint32_t *ad_data, uint32_t key[8], uint32_t nonce[3], size_t num_blocks, size_t num_ad_blocks, uint8_t mac[16])
{

    Chacha20(data, key, nonce, num_blocks);

    size_t message_size = (num_blocks+num_ad_blocks) * 16 * 4;
    uint32_t message[(num_blocks+num_ad_blocks)*16];
    uint32_t mac_key_block[16];

    //Creation of full data message for Poly1305
    memcpy(message, ad_data, num_ad_blocks*16*sizeof(uint32_t));
    memcpy(message + num_ad_blocks*16, data, num_blocks*16*sizeof(uint32_t));

    //Generation of Poly1305 Key
    KeyBlockGeneration(mac_key_block, key, nonce, 0);

    poly1305(mac, message, message_size, mac_key_block);
}