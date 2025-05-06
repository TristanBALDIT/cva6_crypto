#include "cvxif_macros.h" 

  .globl main

main:

  li a0, 0x1;
  li a1, 0x1;
  CUS_ROR64H(01010, 01011, 000001, 01100);

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