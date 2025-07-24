// Copyright 2021 Thales DIS design services SAS
//
// Licensed under the Solderpad Hardware Licence, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0 WITH SHL-2.0
// You may obtain a copy of the License at https://solderpad.org/licenses/
//
// Original Author: Guillaume Chauvon (guillaume.chauvon@thalesgroup.com)



package cvxif_instr_pkg;

  typedef enum logic [3:0] {
    ILLEGAL = 4'b0000,
    NOP = 4'b0001,
    ROR64H = 4'b0010,
    ROR64L = 4'b0011,
    OP_ASCON = 4'b0100,
    OP_CHACHA = 4'b0101,
    MULTI_ROR64H = 4'b0110,
    MULTI_ROR64L = 4'b0111
  } opcode_t;


  typedef struct packed {
    logic accept;
    logic writeback;  // TODO depends on dualwrite
    logic [2:0] register_read;  // TODO Nr read ports
  } issue_resp_t;

  typedef struct packed {
    logic        accept;
    logic [31:0] instr;
  } compressed_resp_t;

  typedef struct packed {
    logic [31:0] instr;
    logic [31:0] mask;
    issue_resp_t resp;
    opcode_t     opcode;
  } copro_issue_resp_t;


  typedef struct packed {
    logic [15:0]      instr;
    logic [15:0]      mask;
    compressed_resp_t resp;
  } copro_compressed_resp_t;

  // 6 Possible RISCV instructions for Coprocessor
  parameter int unsigned NbInstr = 7;
  parameter copro_issue_resp_t CoproInstr[NbInstr] = '{
      '{
          // Custom Nop
          instr:
          32'b00000_00_00000_00000_0_00_00000_1111011,  // custom3 opcode
          mask: 32'b11111_11_00000_00000_1_11_00000_1111111,
          resp : '{accept : 1'b1, writeback : 1'b0, register_read : {1'b0, 1'b0, 1'b0}},
          opcode : NOP
      },
      '{
          // Custom ROR64 High word part
          instr:
          32'b000000_0_00000_00000_000_00000_0001011,  // custom0 opcode
          mask: 32'b000000_0_00000_00000_111_00000_1111111,
          resp : '{accept : 1'b1, writeback : 1'b1, register_read : {1'b0, 1'b1, 1'b1}},
          opcode : ROR64H
      },
      '{
          // Custom ROR64 Low word part
          instr:
          32'b000000_0_00000_00000_001_00000_0001011,  // custom0 opcode
          mask: 32'b000000_0_00000_00000_111_00000_1111111,
          resp : '{accept : 1'b1, writeback : 1'b1, register_read : {1'b0, 1'b1, 1'b1}},
          opcode : ROR64L
      },
    '{
          // Custom OP for ASCON p-function
          instr:
          32'b00000_00_00000_00000_010_00000_0001011,  // custom0 opcode 
          mask: 32'b00000_11_00000_00000_111_00000_1111111,
          resp : '{accept : 1'b1, writeback : 1'b1, register_read : {1'b1, 1'b1, 1'b1}},
          opcode : OP_ASCON
      },
    '{
          // Custom OP for CHACAHA QR-function
          instr:
          32'b00000_00_00000_00000_011_00000_0001011,  // custom0 opcode 
          mask: 32'b00000_00_00000_00000_111_00000_1111111,
          resp : '{accept : 1'b1, writeback : 1'b1, register_read : {1'b1, 1'b1, 1'b1}},
          opcode : OP_CHACHA
      },
      '{
          // custom multi-ROR64 high word part for ASCON
          instr:
          32'b000000_0_00000_00000_100_00000_0001011,  // custom0 opcode 
          mask: 32'b000000_0_00000_00000_111_00000_1111111,
          resp : '{accept : 1'b1, writeback : 1'b1, register_read : {1'b0, 1'b1, 1'b1}},
          opcode : MULTI_ROR64H
      },
      '{
          // custom multi-ROR64 low word part for ASCON
          instr:
          32'b000000_0_00000_00000_101_00000_0001011,  // custom0 opcode 
          mask: 32'b000000_0_00000_00000_111_00000_1111111,
          resp : '{accept : 1'b1, writeback : 1'b1, register_read : {1'b0, 1'b1, 1'b1}},
          opcode : MULTI_ROR64L
      }                
  };

  parameter int unsigned NbCompInstr = 2;
  parameter copro_compressed_resp_t CoproCompInstr[NbCompInstr] = '{
      // C_NOP
      '{
          instr : 16'b111_0_00000_00000_00,
          mask : 16'b111_1_00000_00000_11,
          resp : '{accept : 1'b1, instr : 32'b00000_00_00000_00000_0_00_00000_1111011}
      },
      '{
          instr : 16'b111_1_00000_00000_00,
          mask : 16'b111_1_00000_00000_11,
          resp : '{accept : 1'b1, instr : 32'b00000_00_00000_00000_0_01_01010_1111011}
      }
  };

endpackage
