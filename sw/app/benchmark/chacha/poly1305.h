//
// Created by trist on 21/03/2025.
//

#ifndef POLY1305_H
#define POLY1305_H
#include <stdint.h>
#include <stddef.h>

void poly1305(uint8_t tag[16], const uint8_t *msg, size_t msg_len, const uint8_t key[32]);
static void poly_sum_mul(uint32_t h[5], const uint32_t r[4], uint32_t s[4], size_t block_size );
void test_poly1305();

#endif //POLY1305_H
