// Copyright 2024 Thales DIS France SAS
//
// Licensed under the Solderpad Hardware Licence, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0 WITH SHL-2.0
// You may obtain a copy of the License at https://solderpad.org/licenses/
//
// Original Author: Guillaume Chauvon

module copro_alu
  import cvxif_instr_pkg::*;
#(
    parameter int unsigned NrRgprPorts = 2,
    parameter int unsigned XLEN = 32,
    parameter type hartid_t = logic,
    parameter type id_t = logic,
    parameter type registers_t = logic

) (
    input  logic                  clk_i,
    input  logic                  rst_ni,
    input  registers_t            registers_i,
    input  opcode_t               opcode_i,
    input  hartid_t               hartid_i,
    input  id_t                   id_i,
    input  logic       [     4:0] rd_i,
    input  logic       [     6:0] imm_i,          //custom immediate value
    input  logic       [     1:0] f2_i,           //custom function code
    output logic       [XLEN-1:0] result_o,
    output hartid_t               hartid_o,
    output id_t                   id_o,
    output logic       [     4:0] rd_o,
    output logic                  valid_o,
    output logic                  we_o
    
);

  logic [XLEN-1:0] result_n, result_q;
  hartid_t hartid_n, hartid_q;
  id_t id_n, id_q;
  logic valid_n, valid_q;
  logic [4:0] rd_n, rd_q;
  logic we_n, we_q;

  assign result_o = result_q;
  assign hartid_o = hartid_q;
  assign id_o     = id_q;
  assign valid_o  = valid_q;
  assign rd_o     = rd_q;
  assign we_o     = we_q;

  function automatic logic [31:0] ROR64_HI (
    logic [31:0] hi,
    logic [31:0] lo,
    logic [5:0] imm
  );
    logic [31:0] result;
    if (imm < 32) begin
      result = (hi >> imm) | (lo << (32 - imm)); 
    end else begin
      result = (lo >> imm - 32 ) | (hi << (64 - imm)); 
    end
    return result; // higher part result
  endfunction

  function automatic logic [31:0] ROR64_LO (
    logic [31:0] hi,
    logic [31:0] lo,
    logic [5:0] imm
  );
    logic [31:0] result;
    if (imm < 32) begin
      result = (lo >> imm) | (hi << (32 - imm)); 
    end else begin
      result = (hi >> imm - 32 ) | (lo << (64 - imm)); 
    end
    return result; // lower part result
  endfunction

  function automatic logic [31:0] F_CHACHA (
    logic [31:0] r1,
    logic [31:0] r2,
    logic [31:0] r3,
    logic [1:0] f2
  );
    logic [31:0] result;
    result = (r1 & r2) ^ r3;
    case(f2)
      2'b00: result = ((result << 16) | (result >> 16));
      2'b01: result = ((result << 12) | (result >> 20));
      2'b10: result = ((result << 8) | (result >> 24));
      2'b11: result = ((result << 7) | (result >> 25));
      default: result = '0; // Default case
    endcase
    return result; // Résultat
  endfunction

  function automatic logic [31:0] F_MULTI_ROR64H (
    logic [31:0] hi,
    logic [31:0] lo,
    logic [6:0] imm
  );
    logic [31:0] result;
    case(imm)
      7'b0000000: result = hi ^ ROR64_HI(hi, lo, 19) ^ ROR64_HI(hi, lo, 28); // ROR64H with imm = 19 and 28
      7'b0000001: result = hi ^ ROR64_HI(hi, lo, 61) ^ ROR64_HI(hi, lo, 39); // ROR64H with imm = 61 and 39
      7'b0000010: result = hi ^ ROR64_HI(hi, lo, 1) ^ ROR64_HI(hi, lo, 6); // ROR64H with imm = 1 and 6
      7'b0000011: result = hi ^ ROR64_HI(hi, lo, 10) ^ ROR64_HI(hi, lo, 17); // ROR64H with imm = 10 and 17
      7'b0000100: result = hi ^ ROR64_HI(hi, lo, 7) ^ ROR64_HI(hi, lo, 41); // ROR64H with imm = 7 and 41
      default: result = '0; // Default case
    endcase
    return result; // higher part result
  endfunction  
  
  function automatic logic [31:0] F_MULTI_ROR64L (
    logic [31:0] hi,
    logic [31:0] lo,
    logic [6:0] imm
  );
    logic [31:0] result;
    case(imm)
      7'b0000000: result = lo ^ ROR64_LO(hi, lo, 19) ^ ROR64_LO(hi, lo, 28); // ROR64H with imm = 19 and 28
      7'b0000001: result = lo ^ ROR64_LO(hi, lo, 61) ^ ROR64_LO(hi, lo, 39); // ROR64H with imm = 61 and 39
      7'b0000010: result = lo ^ ROR64_LO(hi, lo, 1) ^ ROR64_LO(hi, lo, 6); // ROR64H with imm = 1 and 6
      7'b0000011: result = lo ^ ROR64_LO(hi, lo, 10) ^ ROR64_LO(hi, lo, 17); // ROR64H with imm = 10 and 17
      7'b0000100: result = lo ^ ROR64_LO(hi, lo, 7) ^ ROR64_LO(hi, lo, 41); // ROR64H with imm = 7 and 41
      default: result = '0; // Default case
    endcase
    return result; // lower part result
  endfunction 

  always_comb begin
    case (opcode_i)
      cvxif_instr_pkg::NOP: begin
        result_n = '0;
        hartid_n = hartid_i;
        id_n     = id_i;
        valid_n  = 1'b1;
        rd_n     = '0;
        we_n     = '0;
      end
      cvxif_instr_pkg::ROR64H: begin
        result_n = ROR64_HI(registers_i[0], registers_i[1], imm_i[6:1]);
        hartid_n = hartid_i;
        id_n = id_i;
        valid_n = 1'b1;
        rd_n = rd_i;
        we_n = 1'b1;
      end
      cvxif_instr_pkg::ROR64L: begin
        result_n = ROR64_LO(registers_i[0], registers_i[1], imm_i[6:1]);
        hartid_n = hartid_i;
        id_n = id_i;
        valid_n = 1'b1;
        rd_n = rd_i;
        we_n = 1'b1;
      end
      cvxif_instr_pkg::OP_ASCON: begin
        result_n = NrRgprPorts == 3 ? registers_i[0] ^ (~ registers_i[1] & registers_i[2]) : 32'b0; 
        hartid_n = hartid_i;
        id_n = id_i;
        valid_n = 1'b1;
        rd_n = rd_i;
        we_n = 1'b1;
      end
      cvxif_instr_pkg::OP_CHACHA: begin
        result_n = NrRgprPorts == 3 ? F_CHACHA(registers_i[0], registers_i[1], registers_i[2], f2_i)   : 32'b0; 
        hartid_n = hartid_i;
        id_n = id_i;
        valid_n = 1'b1;
        rd_n = rd_i;
        we_n = 1'b1;
      end
      cvxif_instr_pkg::MULTI_ROR64H: begin
        result_n = F_MULTI_ROR64H(registers_i[0], registers_i[1], imm_i); 
        hartid_n = hartid_i;
        id_n = id_i;
        valid_n = 1'b1;
        rd_n = rd_i;
        we_n = 1'b1;
      end
      cvxif_instr_pkg::MULTI_ROR64L: begin
        result_n = F_MULTI_ROR64L(registers_i[0], registers_i[1], imm_i); 
        hartid_n = hartid_i;
        id_n = id_i;
        valid_n = 1'b1;
        rd_n = rd_i;
        we_n = 1'b1;
      end
      default: begin
        result_n = '0;
        hartid_n = '0;
        id_n     = '0;
        valid_n  = '0;
        rd_n     = '0;
        we_n     = '0;
      end
    endcase
  end

  always_ff @(posedge clk_i, negedge rst_ni) begin
    if (~rst_ni) begin
      result_q <= '0;
      hartid_q <= '0;
      id_q     <= '0;
      valid_q  <= '0;
      rd_q     <= '0;
      we_q     <= '0;
    end else begin
      result_q <= result_n;
      hartid_q <= hartid_n;
      id_q     <= id_n;
      valid_q  <= valid_n;
      rd_q     <= rd_n;
      we_q     <= we_n;
    end
  end

endmodule
