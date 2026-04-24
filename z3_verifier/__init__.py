"""
Z3 BPF Validator

基于 SMT 的 eBPF Verifier 语义等价性验证工具。

核心思想：给定两个 BPF 程序（原始 bytecode 和 verifier 输出的 bytecode），
在相同的初始状态下，验证两者是否产生相同的 R0（返回值）。

验证策略：
1. 将 BPF bytecode 转换为 Z3 符号表达式
2. 对每个程序做符号执行，得到 R0 的 Z3 符号值
3. 用 Z3 求解器检查 R0 是否等价（SAT = 找到反例，UNSAT = 证明等价）
"""

from .opcode import (
    BPF_CLASS, BPF_OP, BPF_SIZE, BPF_JMP,
    BPF_EXIT, BPF_CALL,
    decode_insn,
)
from .interpreter import (
    parse_bytecode, bytecode_to_str, BPFProgram,
    ALU64, ALU64_K, ALU, ALU_K, JMP, JMP_K, LDX, STX, ST,
    LDDW, MOV, MOV_K, MOV32, MOV32_K, EXIT, CALL, NEG, NEG32, JA,
)
from .semantics import alu32, alu64, jmp_cond
from .verifier import verify_programs
from .tests import TESTS, test
