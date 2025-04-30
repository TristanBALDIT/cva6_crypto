#include "cvxif_macros.h" 

  .globl main

main:

start0:
    LOAD_RS(a0, 12345678)
    LOAD_RS(a1, 12345678)

    CUS_ROR64H(01010, 01011, 01100)

# Take branch to check for instruction kill
    li a0, 0xCAFE;
    li a1, 0xCAFE;
    xor a2, a0, a1;
    beqz a2, branch2;

branch1:
    CUS_ADD(00000, 00000, 01011);
    CUS_NOP();
    CUS_NOP();

branch2:
    CUS_ADD(01010, 01010, 01011);
    lw a0, num1;
    CUS_ADD_RS1(01000,01010,01011);
    lw a1, num2;
    CUS_ADD(01010,01011,00000);


# (example of) final self-check test
    li a0, 0xCAFE;
    li a1, 0xCAFE;
    xor a2, a0, a1;
    beqz a2, pass;

fail:
    # Failure post-processing (messages, ecall setup etc.)
    li a0, 0x0;
    jal exit;

pass:
    # Success post-processing (messages, ecall setup etc.)
    li a0, 0x0;
    jal exit;

.data
    num1:   .word 5      // First number
    num2:   .word 7      // Second number
    result: .word 12      // Result
