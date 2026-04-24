"""
Z3 BPF Validator

向后兼容入口文件。

所有公共 API 已迁移至 z3_verifier 包。此文件保留作为兼容层，
使原有脚本无需修改即可运行。

新代码推荐直接 import z3_verifier。
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from z3_verifier import (
    BPF_CLASS, BPF_OP, BPF_SIZE, BPF_JMP,
    BPF_EXIT, BPF_CALL,
    decode_insn,
    parse_bytecode, bytecode_to_str, BPFProgram,
    ALU64, ALU64_K, ALU, ALU_K, JMP, JMP_K, LDX, STX, ST,
    LDDW, MOV, MOV_K, MOV32, MOV32_K, EXIT, CALL, NEG, NEG32, JA,
    alu32, alu64, jmp_cond,
    verify_programs,
    TESTS, test,
)
from z3_verifier.main import main

__all__ = [
    "BPF_CLASS", "BPF_OP", "BPF_SIZE", "BPF_JMP",
    "BPF_EXIT", "BPF_CALL",
    "decode_insn",
    "parse_bytecode", "bytecode_to_str", "BPFProgram",
    "ALU64", "ALU64_K", "ALU", "ALU_K", "JMP", "JMP_K", "LDX", "STX", "ST",
    "LDDW", "MOV", "MOV_K", "MOV32", "MOV32_K", "EXIT", "CALL", "NEG", "NEG32", "JA",
    "alu32", "alu64", "jmp_cond",
    "verify_programs",
    "TESTS", "test",
    "main",
]

if __name__ == "__main__":
    sys.exit(main())
