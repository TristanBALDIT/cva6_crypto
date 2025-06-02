#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes/aes.h"
#include "chacha/chacha.h"
#include "chacha/poly1305.h"
#include  "loader.h"
#include "ascon/ascon.h"
#include "util.h"


void print_state(uint32_t state[4])
{
    for (int j = 0; j < 4; j++)
    {
        printf("%08X ", state[j]);
    }
    printf("\r\n");
}

void print_chacha_block(uint32_t block[16])
{
    for (int i = 0; i < 16; i++)
    {
        if (i % 4 == 0)
        {
            printf("\r\n");
        }
        printf("%08X ", block[i]);
    }
    printf("\r\n");
}

void min_max_update(size_t value, size_t *min, size_t *max)
{
    if (value < *min)
    {
        *min = value;
    }
    if (value > *max)
    {
        *max = value;
    }
}

int main() {

                           /* KEYS & BLOCKS GENERATION  */

    size_t instret, cycles;

    int iterations = 100;
    int blocks = 80;
    int ad_bits = 512;
    int ad_32b_words = ad_bits/32;
    int ad_64b_words = ad_bits/64;
    int chacha_ad_block = ad_bits / 512;
    int aes_ad_blocks = ad_bits / 128;
    int ascon128a_ad_blocks = ad_bits / 128;
    int ascon128_ad_blocks = ad_bits / 64;

    // Known vector for AES
    uint32_t test_key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
    uint32_t test_state[4] = {
        0x3243F6A8,
        0x885A308D,
        0x313198A2,
        0xE0370734
    };

    // Known test vector for ChaCha20
    uint32_t chacha_test_key[8] = {
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c};
    uint32_t test_nonce[3] = {0x09000000, 0x4a000000, 0x00000000};

    //Know test vector for AES-GCM

    uint32_t aes_gcm_test_key[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t aes_gcm_test_iv[3] = {0x00000000, 0x00000000, 0x00000000};
    uint32_t aes_gcm_test_block[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};
    uint32_t aes_gcm_test_ad[4];
    size_t aes_gcm_test_num_blocks = 1;
    size_t aes_gcm_test_num_ad_blocks = 0;

    // Data generation for AES/CHACHA
    uint32_t *key  = generate_random_32bit_words(8);
    uint32_t *d_blocks = generate_random_32bit_words(16*blocks);
    uint32_t *ad_blocks = generate_random_32bit_words(16*ad_32b_words);
    uint32_t *iv = generate_random_32bit_words(4);
    uint32_t *nonce = generate_random_32bit_words(3);

    uint64_t ciphertext[2*blocks];
    uint64_t tag[2];
    uint64_t *plaintext = generate_random_64bit_words(2*blocks);
    uint64_t *key_ascon = generate_random_64bit_words(2);
    uint64_t *nonce_ascon = generate_random_64bit_words(2);
    uint64_t *ad_data = generate_random_64bit_words(ad_64b_words);
    uint64_t result[2*blocks];

    size_t ce;
    size_t cd;

    size_t max_e = 0;
    size_t min_e = 0;
    size_t max_d = 0;
    size_t min_d = 0;

    printf("RISCV CRYPTO BENCHMARK \r\n\r\n");
    printf("%d iterations , %d blocks, %d additionnal bits \r\n\r\n", iterations, blocks, ad_bits);
    
                            /* AES BENCHMARK */

    printf("AES BENCHMARK \r\n\r\n");

    initialize_aes_sbox();
    printf("Simple Block Encryption-Decryption\r\n\r\n");

    // AES EBC 1 Block - 100 iterations
    for(int i = 4; i < 10; i+=2)
    {
        ce =0, cd = 0;
        printf("KEY SIZE : %d \r\n", 32*i);
        for (int e = 0; e < iterations; e++)
        {
            if (e == 0)
            {
                printf("Plaintext :");
                print_state(test_state);
            }

            instret = -read_csr(minstret);
            cycles = -read_csr(mcycle);

            encryptBlock(test_state, test_key, i);

            instret += read_csr(minstret);
            cycles += read_csr(mcycle);
            ce += cycles;

            if (e == 0)
            {
                printf("Ciphertext :");
                print_state(test_state);
                printf("%d instructions\r\n", (int)(instret));
                printf("%d cycles\r\n\r\n", (int)(cycles));
                min_e = cycles;
                max_e = cycles;
            }

            min_max_update(cycles, &min_e, &max_e);

            instret = -read_csr(minstret);
            cycles = -read_csr(mcycle);

            decryptBlock(test_state, test_key, i);

            instret += read_csr(minstret);
            cycles += read_csr(mcycle);
            cd += cycles;

            if (e == 0)
            {
                printf("Final Plaintext :");
                print_state(test_state);
                printf("%d instructions\r\n", (int)(instret));
                printf("%d cycles\r\n\r\n", (int)(cycles));
                min_d = cycles;
                max_d = cycles;
            }
            min_max_update(cycles, &min_d, &max_d);
        }
        printf("Total cycles for %d iterations :\r\n", iterations);
        printf("Encryption : %d / min: %d / max: %d \r\n", (int) (ce), (int) (min_e), (int) (max_e));
        printf("Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (cd), (int) (min_d), (int) (max_d));
    }


    printf("AES-ECB %d Blocks\r\n", blocks);


    for(int i=4; i < 10; i+=2)
    {
        ce =0, cd = 0;
        printf("KEY SIZE : %d \r\n", 32*i);
        for(int e = 0; e < iterations; e++)
        {

            instret = -read_csr(minstret);
            cycles = -read_csr(mcycle);

            for(int j=0; j < blocks; j++)
            {
                encryptBlock(test_state, test_key, i);
            }

            instret += read_csr(minstret);
            cycles += read_csr(mcycle);
            ce += cycles;

            if(e == 0)
            {
                printf("Encryption : \r\n");
                printf("%d instructions\r\n", (int)(instret));
                printf("%d cycles\r\n\r\n", (int)(cycles));
                min_e = cycles;
                max_e = cycles;
            }
            min_max_update(cycles, &min_e, &max_e);

            instret = -read_csr(minstret);
            cycles = -read_csr(mcycle);

            for(int j=0; j < blocks; j++)
            {
                decryptBlock(test_state, test_key, i);
            }

            instret += read_csr(minstret);
            cycles += read_csr(mcycle);
            cd += cycles;

            if(e == 0)
            {
                printf("Decryption : \r\n");
                printf("%d instructions\r\n", (int)(instret));
                printf("%d cycles\r\n\r\n", (int)(cycles));
                min_d = cycles;
                max_d = cycles;
            }
            min_max_update(cycles, &min_d, &max_d);
        }
        printf("Total cycles for %d iterations :\r\n", iterations);
        printf("Encryption : %d / min: %d / max: %d \r\n", (int) (ce), (int) (min_e), (int) (max_e));
        printf("Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (cd), (int) (min_d), (int) (max_d));
    }


    printf("AES-CBC %d Blocks\r\n", blocks);

    for(int i=4; i < 10; i+=2)
    {
        ce =0, cd = 0;
        printf("KEY SIZE : %d \r\n", 32*i);
        for(int e=0; e < iterations; e++)
        {
            instret = -read_csr(minstret);
            cycles = -read_csr(mcycle);

            aes_cbc_encrypt(d_blocks, blocks, key, iv, i);

            instret += read_csr(minstret);
            cycles += read_csr(mcycle);
            ce += cycles;

            if(e == 0)
            {
                printf("Encryption : \r\n");
                printf("%d instructions\r\n", (int)(instret));
                printf("%d cycles\r\n\r\n", (int)(cycles));
                min_e = cycles;
                max_e = cycles;
            }
            min_max_update(cycles, &min_e, &max_e);

            instret = -read_csr(minstret);
            cycles = -read_csr(mcycle);

            aes_cbc_decrypt(d_blocks, blocks, key, iv, i);

            instret += read_csr(minstret);
            cycles += read_csr(mcycle);
            cd += cycles;

            if(e == 0)
            {
                printf("Decryption : \r\n");
                printf("%d instructions\r\n", (int)(instret));
                printf("%d cycles\r\n\r\n", (int)(cycles));
                min_d = cycles;
                max_d = cycles;
            }
            min_max_update(cycles, &min_d, &max_d);
        }
        printf("Total cycles for %d iterations :\r\n", iterations);
        printf("Encryption : %d / min: %d / max: %d \r\n", (int) (ce), (int) (min_e), (int) (max_e));
        printf("Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (cd), (int) (min_d), (int) (max_d));
    }

    printf("AES-CTR %d Blocks\r\n", blocks);

    for(int i=4; i < 10; i+=2)
    {
        ce =0, cd = 0;
        printf("KEY SIZE : %d \r\n", 32*i);
        for(int e = 0; e < iterations; e++)
        {
            instret = -read_csr(minstret);
            cycles = -read_csr(mcycle);

            aes_ctr(d_blocks, blocks, key, iv, i);

            instret += read_csr(minstret);
            cycles += read_csr(mcycle);
            ce += cycles;

            if(e == 0)
            {
                printf("Encryption - Decryption : \r\n");
                printf("%d instructions\r\n", (int)(instret));
                printf("%d cycles\r\n\r\n", (int)(cycles));
                min_e = cycles;
                max_e = cycles;
            }
            min_max_update(cycles, &min_e, &max_e);
        }
        printf("Total cycles for %d iterations :\r\n", iterations);
        printf("Encryption - Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (ce), (int) (min_e), (int) (max_e));
    }

    printf("AES-GCM Test Vector\r\n");

    uint32_t Test_mac[4];
    aes_gcm(aes_gcm_test_block,aes_gcm_test_ad,1,0,aes_gcm_test_key,aes_gcm_test_iv,4,Test_mac);

    printf("MAC :");
    print_state(Test_mac);

    printf("AES-GCM %d Blocks\r\n", blocks);

    uint32_t T[4];
    for(int i=4; i < 10; i+=2)
    {
        ce =0, cd = 0;
        printf("KEY SIZE : %d \r\n", 32*i);
        for(int e = 0; e < iterations; e++)
        {
            instret = -read_csr(minstret);
            cycles = -read_csr(mcycle);

            aes_gcm(d_blocks, ad_blocks, blocks, aes_ad_blocks, key, iv, i, T);

            instret += read_csr(minstret);
            cycles += read_csr(mcycle);
            ce += cycles;

            if(e == 0)
            {
                printf("Encryption - Decryption : \r\n");
                printf("%d instructions\r\n", (int)(instret));
                printf("%d cycles\r\n\r\n", (int)(cycles));
                min_e = cycles;
                max_e = cycles;
            }
            min_max_update(cycles, &min_e, &max_e);
        }
        printf("Total cycles for %d iterations :\r\n", iterations);
        printf("Encryption - Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (ce), (int) (min_e), (int) (max_e));
    }


                    /* Chacha20 BENCHMARK */

    printf("ChaCha20 Benchmark\r\n\r\n");

    // KeyBlock Test Vector Verification + 1 Block Benchmark
    printf("ChaCha20 KeyBlock Test Vector Verification & 1 Block benchmark\r\n\r\n");

    ce =0, cd = 0;
    for(int e = 0; e < iterations; e++)
    {
        uint32_t counter = e+1;
        uint32_t block[16];

        instret = -read_csr(minstret);
        cycles = -read_csr(mcycle);

        KeyBlockGeneration(block, chacha_test_key, test_nonce, counter);

        instret += read_csr(minstret);
        cycles += read_csr(mcycle);
        ce += cycles;

        if(e == 0)
        {
            printf("Chacha20 1 Block : \r\n");
            printf("%d instructions\r\n", (int)(instret));
            printf("%d cycles\r\n\r\n", (int)(cycles));
            print_chacha_block(block);
            min_e = cycles;
            max_e = cycles;
        }
        min_max_update(cycles, &min_e, &max_e);
    }
    printf("Total cycles for %d iterations :\r\n", iterations);
    printf("Encryption - Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (ce), (int) (min_e), (int) (max_e));

    //Poly1305 Test Vector
    test_poly1305();

    printf("ChaCha20 %d Blocs \r\n\r\n", blocks);

    ce =0, cd = 0;
    for(int e = 0; e < iterations; e++)
    {
        instret = -read_csr(minstret);
        cycles = -read_csr(mcycle);

        Chacha20(d_blocks, key, nonce, blocks);

        instret += read_csr(minstret);
        cycles += read_csr(mcycle);
        ce += cycles;

        if(e == 0)
        {
            printf("Chacha20 10 Block : \r\n");
            printf("%d instructions\r\n", (int)(instret));
            printf("%d cycles\r\n\r\n", (int)(cycles));
            min_e = cycles;
            max_e = cycles;
        }
        min_max_update(cycles, &min_e, &max_e);
    }
    printf("Total cycles for %d iterations :\r\n", iterations);
    printf("Encryption - Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (ce), (int) (min_e), (int) (max_e));

    printf("ChaCha20-Poly1305 %d Blocs \r\n\r\n", blocks);

    uint8_t mac[16];
    ce = 0, cd = 0;
    for(int e = 0; e < iterations; e++)
    {
        instret = -read_csr(minstret);
        cycles = -read_csr(mcycle);

        Chacha20_Poly1305(d_blocks, ad_blocks, key, nonce, blocks, chacha_ad_block, mac);

        instret += read_csr(minstret);
        cycles += read_csr(mcycle);
        ce += cycles;

        if(e == 0)
        {
            printf("Chacha20-Poly1305 10 Block : \r\n");
            printf("%d instructions\r\n", (int)(instret));
            printf("%d cycles\r\n\r\n", (int)(cycles));
            min_e = cycles;
            max_e = cycles;
        }
        min_max_update(cycles, &min_e, &max_e);
    }
    printf("Total cycles for %d iterations :\r\n", iterations);
    printf("Encryption - Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (ce), (int) (min_e), (int) (max_e));

                    /* ASCON BENCHMARK */

    printf("ASCON_128 Test Vector / %d Blocs\r\n\r\n", blocks);

    ce =0, cd = 0;
    for (int e = 0; e < iterations; e++)
    {
        if(e == 0)
        {
            printf("plain\r\n");
            for (int i = 0; i < 10; i++)
            {
                printf("%016llX ", plaintext[i]);
            }
            printf("\r\n");
        }

        instret = -read_csr(minstret);
        cycles = -read_csr(mcycle);

        ASCON_128_encrypt_custom(plaintext, key_ascon, nonce_ascon, ad_data, blocks*64, ad_bits, ciphertext, tag);

        instret += read_csr(minstret);
        cycles += read_csr(mcycle);
        ce += cycles;

        if(e == 0)
        {
            printf("ASCON 10 Block Encrypt: \r\n");
            printf("%d instructions\r\n", (int)(instret));
            printf("%d cycles\r\n\r\n", (int)(cycles));
            printf("cipher\r\n");
            for (int i = 0; i < 10; i++)
            {
                printf("%016llX ", ciphertext[i]);
            }
            printf("\r\n");
            min_e = cycles;
            max_e = cycles;
        }
        min_max_update(cycles, &min_e, &max_e);

        instret = -read_csr(minstret);
        cycles = -read_csr(mcycle);

        ASCON_128_decrypt_custom(result, key_ascon, nonce_ascon, ad_data, 64*blocks, ad_bits, ciphertext, tag);

        instret += read_csr(minstret);
        cycles += read_csr(mcycle);
        cd += cycles;

        if(e == 0)
        {
            printf("ASCON_128 10 Blocks Decrypt : \r\n");
            printf("%d instructions\r\n", (int)(instret));
            printf("%d cycles\r\n\r\n", (int)(cycles));
            printf("plain \r\n");
            for (int i = 0; i < 10; i++)
            {
                printf("%016llX ", result[i]);
            }
            printf("\r\n");
            min_d = cycles;
            max_d = cycles;
        }
        min_max_update(cycles, &min_d, &max_d);
    }
    printf("Total cycles for %d iterations :\r\n", iterations);
    printf("Encryption : %d / min: %d / max: %d \r\n", (int) (ce), (int) (min_e), (int) (max_e));
    printf("Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (cd), (int) (min_d), (int) (max_d));


    printf("ASCON_128a %d Blocks\r\n\r\n", blocks);

    ce =0, cd = 0;
    for(int e = 0; e < iterations; e++)
    {

        if(e == 0)
        {
            printf("plain\r\n");
            for (int i = 0; i < 10; i++)
            {
                printf("%016llX ", plaintext[i]);
            }
            printf("\r\n");
        }

        instret = -read_csr(minstret);
        cycles = -read_csr(mcycle);

        ASCON_128a_encrypt_custom(plaintext, key_ascon, nonce_ascon, ad_data, blocks*128, ad_bits, ciphertext, tag);

        instret += read_csr(minstret);
        cycles += read_csr(mcycle);
        ce += cycles;

        if(e == 0)
        {
            printf("ASCON_128a 10 Block Encrypt: \r\n");
            printf("%d instructions\r\n", (int)(instret));
            printf("%d cycles\r\n\r\n", (int)(cycles));

            printf("cipher\r\n");
            for (int i = 0; i < 10; i++)
            {
                printf("%016llX ", ciphertext[i]);
            }
            printf("\r\n");
            min_e = cycles;
            max_e = cycles;
        }
        min_max_update(cycles, &min_e, &max_e);

        instret = -read_csr(minstret);
        cycles = -read_csr(mcycle);

        ASCON_128a_decrypt_custom(result, key_ascon, nonce_ascon, ad_data, 128*blocks, ad_bits, ciphertext, tag);

        instret += read_csr(minstret);
        cycles += read_csr(mcycle);
        cd += cycles;

        if(e == 0)
        {
            printf("ASCON_128a 10 Blocks Decrypt : \r\n");
            printf("%d instructions\r\n", (int)(instret));
            printf("%d cycles\r\n\r\n", (int)(cycles));

            printf("plain\r\n");
            for (int i = 0; i < 10; i++)
            {
                printf("%016llX ", result[i]);
            }
            printf("\r\n");
            min_d = cycles;
            max_d = cycles;
        }
        min_max_update(cycles, &min_d, &max_d);
    }
    printf("Total cycles for %d iterations :\r\n", iterations);
    printf("Encryption : %d / min: %d / max: %d \r\n", (int) (ce), (int) (min_e), (int) (max_e));
    printf("Decryption : %d / min: %d / max: %d \r\n\r\n\r\n", (int) (cd), (int) (min_d), (int) (max_d));

    //Free
    free(key);
    free(d_blocks);
    free(ad_blocks);
    free(nonce);
    free(iv);
    free(plaintext);
    free(key_ascon);
    free(nonce_ascon);
    free(ad_data);

    return 0;
}

