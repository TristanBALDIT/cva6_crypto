//
// Created by trist on 24/03/2025.
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "ascon.h"
#include "asm.h"

uint64_t rc[12] = {
    0x00000000000000f0, 0x00000000000000e1, 0x00000000000000d2,
    0x00000000000000c3, 0x00000000000000b4, 0x00000000000000a5,
    0x0000000000000096, 0x0000000000000087, 0x0000000000000078,
    0x0000000000000069, 0x000000000000005a, 0x000000000000004b
};

void p(uint64_t state[5], uint64_t n)
{
    for(int i = 0; i < n; i++)
    {
        state[2] ^= rc[i];

        uint64_t temp[5];
        state[0] ^= state[4], state[4] ^= state[3], state[2] ^= state[1];
        temp[0] = state[0], temp[1] = state[1], temp[2] = state[2], temp[3] = state[3], temp[4] = state[4];
        temp[0] =~ temp[0], temp[1] =~  temp[1], temp[2] =~  temp[2], temp[3] =~ temp[3], temp[4] =~ temp[4];
        temp[0] &= state[1], temp[1] &= state[2], temp[2] &= state[3], temp[3] &= state[4], temp[4] &= state[0];
        state[0] ^= temp[1], state[1] ^= temp[2], state[2] ^= temp[3], state[3] ^= temp[4], state[4] ^= state[0];
        state[1] ^= state[0], state[0] ^= state[4], state[3] ^= state[2], state[2] =~ state[2];

        state[0] = state[0] ^ ROR64(state[0], 19) ^ ROR64(state[0], 28);
        state[1] = state[1] ^ ROR64(state[1], 61) ^ ROR64(state[1], 39);
        state[2] = state[2] ^ ROR64(state[2], 1) ^ ROR64(state[2], 6);
        state[3] = state[3] ^ ROR64(state[3], 10) ^ ROR64(state[3], 17);
        state[4] = state[4] ^ ROR64(state[4], 7) ^ ROR64(state[4], 41);
    }
}

void p_asm(uint64_t state[5], uint64_t n) {
    for(int i = 0; i < n; i++)
    {
        state[2] ^= rc[i];

        uint64_t temp[2];
        state[0] ^= state[4], state[4] ^= state[3], state[2] ^= state[1];
        temp[0] = custom_OP_ASCON(state[0], state[1], state[2]);
        temp[1] = custom_OP_ASCON(state[1], state[2], state[3]);
        state[2] = custom_OP_ASCON(state[2], state[3], state[4]);
        state[3] = custom_OP_ASCON(state[3], state[4], state[0]);
        state[4] = custom_OP_ASCON(state[4], state[0], state[1]);
        state[0] = temp[0] ^ state[4] , state[1] = temp[1] ^ temp[0], state[3] ^= state[2], state[2] = ~ state[2];

        uint32_t* s32 = (uint32_t*)state;
        s32[0] = s32[0] ^ custom_ROR64L_19(s32[1], s32[0]) ^ custom_ROR64L_28(s32[1], s32[0]);
        s32[1] = s32[1] ^ custom_ROR64H_19(s32[1], s32[0]) ^ custom_ROR64H_28(s32[1], s32[0]);
        s32[2] = s32[2] ^ custom_ROR64L_61(s32[3], s32[2]) ^ custom_ROR64L_39(s32[3], s32[2]);
        s32[3] = s32[3] ^ custom_ROR64H_61(s32[3], s32[2]) ^ custom_ROR64H_39(s32[3], s32[2]);
        s32[4] = s32[4] ^ custom_ROR64L_1(s32[5], s32[4]) ^ custom_ROR64L_6(s32[5], s32[4]);
        s32[5] = s32[5] ^ custom_ROR64H_1(s32[5], s32[4]) ^ custom_ROR64H_6(s32[5], s32[4]);
        s32[6] = s32[6] ^ custom_ROR64L_10(s32[7], s32[6]) ^ custom_ROR64L_17(s32[7], s32[6]);
        s32[7] = s32[7] ^ custom_ROR64H_10(s32[7], s32[6]) ^ custom_ROR64H_17(s32[7], s32[6]);
        s32[8] = s32[8] ^ custom_ROR64L_7(s32[9], s32[8]) ^ custom_ROR64L_41(s32[9], s32[8]);
        s32[9] = s32[9] ^ custom_ROR64H_7(s32[9], s32[8]) ^ custom_ROR64H_41(s32[9], s32[8]);
    }
}

void ASCON_128_encrypt(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag)
{
    size_t l = len_data % 64;
    size_t n = len_ad_data % 64;

    size_t num_blocks = (len_data+63) / 64;         //+63 to count incomplete blocks
    size_t num_ad_blocks = (len_ad_data+63) / 64;   //+63 to count incomplete blocks

    if (l != 0)
    {
        data[num_blocks-1] = (data[num_blocks-1] << (64-l)) | (0x1 << (63-l));
    }
    if(n != 0)
    {
        ad_data[num_ad_blocks-1] = (ad_data[num_ad_blocks-1] << (64-n)) | (0x1 << (63-n));
    }

    uint64_t state[5];
    state[0] = 0x80400c0600000000;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    p(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];

    for(int i = 0; i < num_ad_blocks; i++)
    {
        state[0] ^= ad_data[i];
        p(state,6);
    }
    state[4] ^= 0x0000000000000001;

    for(int i = 0; i < num_blocks-1; i++)
    {
        state[0] ^= data[i];
        ciphertext[i] = state[0];
        p(state,6);
    }

    state[0] ^= data[num_blocks-1];
    if(l != 0)
    {
        ciphertext[num_blocks-1] = (state[0] >> (64-l));
    }
    else
    {
        ciphertext[num_blocks-1] = state[0];
    }

    state[1] ^= key[0];
    state[2] ^= key[1];
    p(state, 12);

    tag[0] = state[3] ^ key[0];
    tag[1] = state[4] ^ key[1];

}

void ASCON_128_decrypt(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag)
{
    size_t l = len_data % 64;
    size_t n = len_ad_data % 64;

    size_t num_blocks = (len_data+63) / 64;
    size_t num_ad_blocks = (len_ad_data+63) / 64;

    if(n != 0)
    {
        ad_data[num_ad_blocks-1] = (ad_data[num_ad_blocks-1] << (64-n)) | (0x1 << (63-n));
    }

    uint64_t state[5];
    state[0] = 0x80400c0600000000;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    p(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];

    for(int i = 0; i < num_ad_blocks; i++)
    {
        state[0] ^= ad_data[i];
        p(state,6);
    }
    state[4] ^= 0x0000000000000001;

    for(int i = 0; i < num_blocks-1; i++)
    {
        data[i] = state[0] ^ ciphertext[i];
        state[0] = ciphertext[i];
        p(state,6);
    }

    if(l != 0)
    {
        data[num_blocks-1] = (state[0] >> (64-l)) ^ ciphertext[num_blocks-1];
        state[0] ^= (data[num_blocks-1] << (64-l)) | (0x1 << (63-l));
    }
    else
    {
        data[num_blocks-1] = state[0] ^ ciphertext[num_blocks-1];
        state[0] = ciphertext[num_blocks-1];
    }

    state[1] ^= key[0];
    state[2] ^= key[1];
    p(state, 12);

    tag[0] = state[3] ^ key[0];
    tag[1] = state[4] ^ key[1];
}


void ASCON_128a_encrypt(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag)
{
    size_t l = len_data % 128;
    size_t n = len_ad_data % 128;

    size_t num_blocks = (len_data+127) / 128;         //+127 to count incomplete blocks
    size_t num_ad_blocks = (len_ad_data+127) / 128;   //+127 to count incomplete blocks

    if (l != 0)
    {
        if(l < 64)
        {
            data[2*num_blocks-2] = (data[2*num_blocks-1] << (64-l)) | (0x1 << (63-l));
            data[2*num_blocks-1] = 0;
        }
        else
        {
            data[2*num_blocks-2] = (data[2*num_blocks-2] << (128-l)) | (data[2*num_blocks-1] >> (l-64));
            data[2*num_blocks-1] = (data[2*num_blocks-1] << (128-l)) | (0x1 << (127-l));
        }
    }
    if(n != 0)
    {
        if(n < 64)
        {
            ad_data[2*num_ad_blocks-2] = (ad_data[2*num_ad_blocks-1] << (64-n)) | (0x1 << (63-n));
            ad_data[2*num_ad_blocks-1] = 0;
        }
        else
        {
            ad_data[2*num_ad_blocks-2] = (ad_data[2*num_ad_blocks-2] << (128-n)) | (ad_data[2*num_ad_blocks-1] >> (n-64));
            ad_data[2*num_ad_blocks-1] = (ad_data[2*num_ad_blocks-1] << (128-n)) | (0x1 << (127-n));
        }
    }

    uint64_t state[5];
    state[0] = 0x80800c0800000000;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    p(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];

    for(int i = 0; i < num_ad_blocks; i++)
    {
        state[0] ^= ad_data[2*i];
        state[1] ^= ad_data[2*i+1];
        p(state,8);
    }
    state[4] ^= 0x0000000000000001;

    for(int i = 0; i < num_blocks-1; i++)
    {
        state[0] ^= data[2*i];
        state[1] ^= data[2*i+1];
        ciphertext[2*i] = state[0];
        ciphertext[2*i+1] = state[1];
        p(state,8);
    }

    state[0] ^= data[2*num_blocks-2];
    state[1] ^= data[2*num_blocks-1];
    if(l != 0)
    {
        if(l < 64)
        {
            ciphertext[2*num_blocks-1] = (state[0] >> (64-l));
            ciphertext[2*num_blocks-2] = 0;
        }
        else
        {
            ciphertext[2*num_blocks-1] = (state[0] << (l-64)) | (state[1] >> (128-l));
            ciphertext[2*num_blocks-2] = (state[0] >> (128-l));
        }
    }
    else
    {
        ciphertext[2*num_blocks-2] = state[0];
        ciphertext[2*num_blocks-1] = state[1];
    }

    state[2] ^= key[0];
    state[3] ^= key[1];
    p(state, 12);

    tag[0] = state[3] ^ key[0];
    tag[1] = state[4] ^ key[1];
}

void ASCON_128a_decrypt(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag)
{
    size_t l = len_data % 128;
    size_t n = len_ad_data % 128;

    size_t num_blocks = (len_data+127) / 128;         //+127 to count incomplete blocks
    size_t num_ad_blocks = (len_ad_data+127) / 128;   //+127 to count incomplete blocks

    if(n != 0)
    {
        if(n < 64)
        {
            ad_data[2*num_ad_blocks-2] = (ad_data[2*num_ad_blocks-1] << (64-n)) | (0x1 << (63-n));
            ad_data[2*num_ad_blocks-1] = 0;
        }
        else
        {
            ad_data[2*num_ad_blocks-2] = (ad_data[2*num_ad_blocks-2] << (128-n)) | (ad_data[2*num_ad_blocks-1] >> (n-64));
            ad_data[2*num_ad_blocks-1] = (ad_data[2*num_ad_blocks-1] << (128-n)) | (0x1 << (127-n));
        }
    }

    uint64_t state[5];
    state[0] = 0x80800c0800000000;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    p(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];

    for(int i = 0; i < num_ad_blocks; i++)
    {
        state[0] ^= ad_data[2*i];
        state[1] ^= ad_data[2*i+1];
        p(state,8);
    }
    state[4] ^= 0x0000000000000001;

    for(int i = 0; i < num_blocks-1; i++)
    {
        data[2*i] = state[0] ^ ciphertext[2*i];
        data[2*i+1] = state[1] ^ ciphertext[2*i+1];
        state[0] = ciphertext[2*i];
        state[1] = ciphertext[2*i+1];
        p(state,8);
    }

    if(l != 0)
    {
        if(l < 64)
        {
            data[2*num_blocks-1] = (state[0] >> (64-l)) ^ ciphertext[2*num_blocks-1];
            data[2*num_blocks-2] = 0;
            state[0] ^= (data[2*num_blocks-1] << (64-l)) | (0x1 << (63-l));
        }
        else
        {
            data[2*num_blocks-2] = (state[0] >> (128-l)) ^ ciphertext[2*num_blocks-2];
            data[2*num_blocks-2] = ((state[0] << (l-64)) | (state[1] >> (128-l))) ^ ciphertext[2*num_blocks-1];
            state[0] ^= (data[2*num_blocks-2] << (128-l)) | (data[2*num_blocks-1] >> (l-64));
            state[1] ^= data[2*num_blocks-1] = (data[2*num_blocks-1] << (128-l)) | (0x1 << (127-l));
        }
    }
    else
    {
        data[2*num_blocks-2] = state[0] ^ ciphertext[2*num_blocks-2];
        data[2*num_blocks-1] = state[1] ^ ciphertext[2*num_blocks-1];
        state[0] = ciphertext[2*num_blocks-2];
        state[1] = ciphertext[2*num_blocks-1];
    }

    state[2] ^= key[0];
    state[3] ^= key[1];
    p(state, 12);

    tag[0] = state[3] ^ key[0];
    tag[1] = state[4] ^ key[1];
}

void ASCON_128_encrypt_custom(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag)
{
    size_t l = len_data % 64;
    size_t n = len_ad_data % 64;

    size_t num_blocks = (len_data+63) / 64;         //+63 to count incomplete blocks
    size_t num_ad_blocks = (len_ad_data+63) / 64;   //+63 to count incomplete blocks

    if (l != 0)
    {
        data[num_blocks-1] = (data[num_blocks-1] << (64-l)) | (0x1 << (63-l));
    }
    if(n != 0)
    {
        ad_data[num_ad_blocks-1] = (ad_data[num_ad_blocks-1] << (64-n)) | (0x1 << (63-n));
    }

    uint64_t state[5];
    state[0] = 0x80400c0600000000;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    p_asm(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];

    for(int i = 0; i < num_ad_blocks; i++)
    {
        state[0] ^= ad_data[i];
        p_asm(state,6);
    }
    state[4] ^= 0x0000000000000001;

    for(int i = 0; i < num_blocks-1; i++)
    {
        state[0] ^= data[i];
        ciphertext[i] = state[0];
        p_asm(state,6);
    }

    state[0] ^= data[num_blocks-1];
    if(l != 0)
    {
        ciphertext[num_blocks-1] = (state[0] >> (64-l));
    }
    else
    {
        ciphertext[num_blocks-1] = state[0];
    }

    state[1] ^= key[0];
    state[2] ^= key[1];
    p_asm(state, 12);

    tag[0] = state[3] ^ key[0];
    tag[1] = state[4] ^ key[1];

}

void ASCON_128_decrypt_custom(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag)
{
    size_t l = len_data % 64;
    size_t n = len_ad_data % 64;

    size_t num_blocks = (len_data+63) / 64;
    size_t num_ad_blocks = (len_ad_data+63) / 64;

    if(n != 0)
    {
        ad_data[num_ad_blocks-1] = (ad_data[num_ad_blocks-1] << (64-n)) | (0x1 << (63-n));
    }

    uint64_t state[5];
    state[0] = 0x80400c0600000000;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    p_asm(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];

    for(int i = 0; i < num_ad_blocks; i++)
    {
        state[0] ^= ad_data[i];
        p_asm(state,6);
    }
    state[4] ^= 0x0000000000000001;

    for(int i = 0; i < num_blocks-1; i++)
    {
        data[i] = state[0] ^ ciphertext[i];
        state[0] = ciphertext[i];
        p_asm(state,6);
    }

    if(l != 0)
    {
        data[num_blocks-1] = (state[0] >> (64-l)) ^ ciphertext[num_blocks-1];
        state[0] ^= (data[num_blocks-1] << (64-l)) | (0x1 << (63-l));
    }
    else
    {
        data[num_blocks-1] = state[0] ^ ciphertext[num_blocks-1];
        state[0] = ciphertext[num_blocks-1];
    }

    state[1] ^= key[0];
    state[2] ^= key[1];
    p_asm(state, 12);

    tag[0] = state[3] ^ key[0];
    tag[1] = state[4] ^ key[1];
}


void ASCON_128a_encrypt_custom(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag)
{
    size_t l = len_data % 128;
    size_t n = len_ad_data % 128;

    size_t num_blocks = (len_data+127) / 128;         //+127 to count incomplete blocks
    size_t num_ad_blocks = (len_ad_data+127) / 128;   //+127 to count incomplete blocks

    if (l != 0)
    {
        if(l < 64)
        {
            data[2*num_blocks-2] = (data[2*num_blocks-1] << (64-l)) | (0x1 << (63-l));
            data[2*num_blocks-1] = 0;
        }
        else
        {
            data[2*num_blocks-2] = (data[2*num_blocks-2] << (128-l)) | (data[2*num_blocks-1] >> (l-64));
            data[2*num_blocks-1] = (data[2*num_blocks-1] << (128-l)) | (0x1 << (127-l));
        }
    }
    if(n != 0)
    {
        if(n < 64)
        {
            ad_data[2*num_ad_blocks-2] = (ad_data[2*num_ad_blocks-1] << (64-n)) | (0x1 << (63-n));
            ad_data[2*num_ad_blocks-1] = 0;
        }
        else
        {
            ad_data[2*num_ad_blocks-2] = (ad_data[2*num_ad_blocks-2] << (128-n)) | (ad_data[2*num_ad_blocks-1] >> (n-64));
            ad_data[2*num_ad_blocks-1] = (ad_data[2*num_ad_blocks-1] << (128-n)) | (0x1 << (127-n));
        }
    }

    uint64_t state[5];
    state[0] = 0x80800c0800000000;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    p_asm(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];

    for(int i = 0; i < num_ad_blocks; i++)
    {
        state[0] ^= ad_data[2*i];
        state[1] ^= ad_data[2*i+1];
        p_asm(state,8);
    }
    state[4] ^= 0x0000000000000001;

    for(int i = 0; i < num_blocks-1; i++)
    {
        state[0] ^= data[2*i];
        state[1] ^= data[2*i+1];
        ciphertext[2*i] = state[0];
        ciphertext[2*i+1] = state[1];
        p_asm(state,8);
    }

    state[0] ^= data[2*num_blocks-2];
    state[1] ^= data[2*num_blocks-1];
    if(l != 0)
    {
        if(l < 64)
        {
            ciphertext[2*num_blocks-1] = (state[0] >> (64-l));
            ciphertext[2*num_blocks-2] = 0;
        }
        else
        {
            ciphertext[2*num_blocks-1] = (state[0] << (l-64)) | (state[1] >> (128-l));
            ciphertext[2*num_blocks-2] = (state[0] >> (128-l));
        }
    }
    else
    {
        ciphertext[2*num_blocks-2] = state[0];
        ciphertext[2*num_blocks-1] = state[1];
    }

    state[2] ^= key[0];
    state[3] ^= key[1];
    p_asm(state, 12);

    tag[0] = state[3] ^ key[0];
    tag[1] = state[4] ^ key[1];
}

void ASCON_128a_decrypt_custom(uint64_t *data, const uint64_t key[2], const uint64_t nonce[2], uint64_t *ad_data,
    const size_t len_data, const size_t len_ad_data, uint64_t *ciphertext, uint64_t *tag)
{
    size_t l = len_data % 128;
    size_t n = len_ad_data % 128;

    size_t num_blocks = (len_data+127) / 128;         //+127 to count incomplete blocks
    size_t num_ad_blocks = (len_ad_data+127) / 128;   //+127 to count incomplete blocks

    if(n != 0)
    {
        if(n < 64)
        {
            ad_data[2*num_ad_blocks-2] = (ad_data[2*num_ad_blocks-1] << (64-n)) | (0x1 << (63-n));
            ad_data[2*num_ad_blocks-1] = 0;
        }
        else
        {
            ad_data[2*num_ad_blocks-2] = (ad_data[2*num_ad_blocks-2] << (128-n)) | (ad_data[2*num_ad_blocks-1] >> (n-64));
            ad_data[2*num_ad_blocks-1] = (ad_data[2*num_ad_blocks-1] << (128-n)) | (0x1 << (127-n));
        }
    }

    uint64_t state[5];
    state[0] = 0x80800c0800000000;
    state[1] = key[0];
    state[2] = key[1];
    state[3] = nonce[0];
    state[4] = nonce[1];

    p_asm(state, 12);
    state[3] ^= key[0];
    state[4] ^= key[1];

    for(int i = 0; i < num_ad_blocks; i++)
    {
        state[0] ^= ad_data[2*i];
        state[1] ^= ad_data[2*i+1];
        p_asm(state,8);
    }
    state[4] ^= 0x0000000000000001;

    for(int i = 0; i < num_blocks-1; i++)
    {
        data[2*i] = state[0] ^ ciphertext[2*i];
        data[2*i+1] = state[1] ^ ciphertext[2*i+1];
        state[0] = ciphertext[2*i];
        state[1] = ciphertext[2*i+1];
        p_asm(state,8);
    }

    if(l != 0)
    {
        if(l < 64)
        {
            data[2*num_blocks-1] = (state[0] >> (64-l)) ^ ciphertext[2*num_blocks-1];
            data[2*num_blocks-2] = 0;
            state[0] ^= (data[2*num_blocks-1] << (64-l)) | (0x1 << (63-l));
        }
        else
        {
            data[2*num_blocks-2] = (state[0] >> (128-l)) ^ ciphertext[2*num_blocks-2];
            data[2*num_blocks-2] = ((state[0] << (l-64)) | (state[1] >> (128-l))) ^ ciphertext[2*num_blocks-1];
            state[0] ^= (data[2*num_blocks-2] << (128-l)) | (data[2*num_blocks-1] >> (l-64));
            state[1] ^= data[2*num_blocks-1] = (data[2*num_blocks-1] << (128-l)) | (0x1 << (127-l));
        }
    }
    else
    {
        data[2*num_blocks-2] = state[0] ^ ciphertext[2*num_blocks-2];
        data[2*num_blocks-1] = state[1] ^ ciphertext[2*num_blocks-1];
        state[0] = ciphertext[2*num_blocks-2];
        state[1] = ciphertext[2*num_blocks-1];
    }

    state[2] ^= key[0];
    state[3] ^= key[1];
    p_asm(state, 12);

    tag[0] = state[3] ^ key[0];
    tag[1] = state[4] ^ key[1];
}


