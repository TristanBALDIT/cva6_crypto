//
// Created by trist on 15/05/2025.
//
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
//#include "util.h"

int main ()
{
    uint32_t w_high = 0x11223344;
    uint32_t w_low = 0x55667788;
    uint32_t result;

    printf("High word : ");
    printf("%08"  PRIX32 "\r\n", w_high );
    printf("Low word : ");
    printf("%08"  PRIX32 "\r\n", w_low );

    asm volatile (
        "mv a0, %[hw]\n\t"
        "mv a1, %[lw]\n\t"
        ".word 0x04B5060B\n\t"
        "mv %[res], a2\n\t"
        : [res] "=r" (result)
        : [hw] "r"(w_high), [lw] "r"(w_low)
        : "a2", "a0", "a1"
    );

    printf("High word after ROR64 : ");
    printf("%08"  PRIX32 "\r\n", result);

    asm volatile (
        ".insn r CUSTOM_0, 0, 64, %[rd], %[rs1], %[rs2]\n\t"
        : [rd] "=r" (result)
        : [rs1] "r"(w_high), [rs2] "r"(w_low)
    );

    printf("High word after second ROR64 : ");
    printf("%08"  PRIX32 "\r\n", result);

    return 0;
}
