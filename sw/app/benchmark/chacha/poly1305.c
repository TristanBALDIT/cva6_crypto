//
// Created by trist on 21/03/2025.
//

#include "poly1305.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#define BLOCK_SIZE 16



void poly1305(uint8_t mac[16], const uint8_t *message, size_t message_size, const uint8_t key[32]) {
    uint32_t r[4], h[5] = {0}, pad[4];
    memcpy(r, key, 16);
    memcpy(pad, key + 16, 16);

    r[0] &= 0x0fffffff; r[1] &= 0x0ffffffc;
    r[2] &= 0x0ffffffc; r[3] &= 0x0ffffffc;

    while (message_size > 0) {
        uint32_t s[4] = {0};
        size_t block_size = message_size < 16 ? message_size : 16;
        memcpy(s, message, block_size);
        if (block_size < 16) s[block_size / 4] |= (1 << (8 * (block_size % 4)));

        poly_sum_mul(h,r,s,block_size);

        // printf("%llu", block_size);
        // printf("\n%02x ", h[0]);
        // printf("%02x ", h[1]);
        // printf("%02x ", h[2]);
        // printf("%02x ", h[3]);
        // printf("%02x\n", h[4]);

        message += block_size;
        message_size -= block_size;
    }

    uint64_t c = 5;
    for (int i = 0; i < 4; i++) {
        c += h[i];
        c >>= 32;
    }
    c += h[4];
    c = (c >> 2) * 5;

    for (int i = 0; i < 4; i++) {
        c += (uint64_t)h[i] + pad[i];
        *(uint32_t *)(mac + i * 4) = (uint32_t)c;
        c >>= 32;
    }
}


void test_poly1305() {
    uint8_t key[32] = {
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
    };
    uint8_t msg[] = "Cryptographic Forum Research Group";
    uint8_t expected_tag[16] = {
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9
    };
    uint8_t tag[16];

    poly1305(tag, msg, strlen((char*)msg), key);

    printf("Tag calcule : ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", tag[i]);
    }
    printf("\n\n");

}

// Multiplies h and r, put the result in h
static void poly_sum_mul(uint32_t h[5], const uint32_t r[4], uint32_t s[4], size_t block_size )
{


    uint64_t s0 = h[0] + (uint64_t) s[0];
    uint64_t s1 = h[1] + (uint64_t) s[1];
    uint64_t s2 = h[2] + (uint64_t) s[2];
    uint64_t s3 = h[3] + (uint64_t) s[3];
    uint32_t s4= h[4] + (block_size == 16);

    //printf("%02x ", s4);


    // These would fit in 32 bits, but we need 64 bit multiplications
    const uint64_t r0 = r[0];
    const uint64_t r1 = r[1];
    const uint64_t r2 = r[2];
    const uint64_t r3 = r[3];
    const uint64_t rr0 = (r[0] >> 2) * 5; // lose 2 bottom bits...
    const uint64_t rr1 = (r[1] >> 2) * 5; // 2 bottom bits already cleared
    const uint64_t rr2 = (r[2] >> 2) * 5; // 2 bottom bits already cleared
    const uint64_t rr3 = (r[3] >> 2) * 5; // 2 bottom bits already cleared

    // school book modular multiplication (without carry propagation)
    const uint64_t x0 = s0*r0 + s1*rr3 + s2*rr2 + s3*rr1 + s4*rr0;
    const uint64_t x1 = s0*r1 + s1*r0  + s2*rr3 + s3*rr2 + s4*rr1;
    const uint64_t x2 = s0*r2 + s1*r1  + s2*r0  + s3*rr3 + s4*rr2;
    const uint64_t x3 = s0*r3 + s1*r2  + s2*r1  + s3*r0  + s4*rr3;
    const uint64_t x4 = s4 * (r0 & 3); // ...recover those 2 bits

    // carry propagation (put the result back in h)
    const uint64_t msb = x4 + (x3 >> 32);
    uint64_t       u   = (msb >> 2) * 5; // lose 2 bottom bits...
    u += (x0 & 0xffffffff)             ;  h[0] = u & 0xffffffff;  u >>= 32;
    u += (x1 & 0xffffffff) + (x0 >> 32);  h[1] = u & 0xffffffff;  u >>= 32;
    u += (x2 & 0xffffffff) + (x1 >> 32);  h[2] = u & 0xffffffff;  u >>= 32;
    u += (x3 & 0xffffffff) + (x2 >> 32);  h[3] = u & 0xffffffff;  u >>= 32;
    u += msb & 3 /* ...recover them */ ;  h[4] = u;
}












