#include <stdio.h>
#include <stdint.h>
#include "aes.h"
#include "util.h"


int main(){

    size_t instret, cycles;

    uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};

    uint32_t data[12] = {
        0x3243f6a8,
        0x885a308d,
        0x313198a2,
        0xe0370734
    };
    

    initialize_aes_sbox();
    
    instret = -read_csr(minstret);
    cycles = -read_csr(mcycle);

    encryptBlock(data, key, KEY_SIZE_128);

    instret += read_csr(minstret);
    cycles += read_csr(mcycle);
    
    printf(" AES");
    printf("%d instructions\n", (int)(instret));
    printf("%d cycles\n", (int)(cycles));
    
    return 0;

}
