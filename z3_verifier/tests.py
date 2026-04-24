"""
内置测试用例。
"""

from .interpreter import (
    parse_bytecode, bytecode_to_str, BPFProgram,
    ALU64, ALU64_K, ALU, ALU_K, JMP, JMP_K, LDX, STX, ST,
    LDDW, MOV, MOV_K, MOV32, MOV32_K, EXIT, CALL, NEG, NEG32, JA,
)
from .verifier import verify_programs


TESTS = {}


def test(name: str):
    """测试装饰器"""
    def deco(f):
        TESTS[name] = f
        return f
    return deco


@test("UDIV32")
def test_udiv32():
    input_prog_raw = [
        MOV32(1, 0),
        ALU_K(0x5, 1, 8),
        ALU_K(0x6, 1, 1),
        MOV_K(2, 0),
        JMP_K(0x5, 2, 2, 0),
        ALU(0x7, 1, 1),
        JA(1),
        ALU(0x3, 1, 2),
        MOV_K(0, 0),
        EXIT(),
    ]

    output_prog_raw = [
        MOV32(1, 0),
        ALU_K(0x5, 1, 8),
        ALU_K(0x6, 1, 1),
        MOV_K(2, 0),
        JMP_K(0x5, 2, 2, 0),
        ALU(0x7, 1, 1),
        JA(1),
        MOV(5, 2),
        ALU64_K(0x0, 5, 1),
        JMP_K(0x2, 5, 4, 1),
        JMP_K(0x1, 5, 1, 0),
        MOV_K(1, 0),
        NEG(1),
        JA(1),
        ALU(0x3, 1, 2),
        MOV_K(0, 0),
        EXIT(),
    ]

    insns_in = parse_bytecode(input_prog_raw)
    insns_out = parse_bytecode(output_prog_raw)

    print("=== INPUT Program (原始) ===")
    print(bytecode_to_str(insns_in))
    print()
    print("=== OUTPUT Program (Verifier 输出) ===")
    print(bytecode_to_str(insns_out))
    print()

    prog_in = BPFProgram(insns_in, "input")
    prog_out = BPFProgram(insns_out, "output")
    reg_constraints = {2: 0}
    print(f"寄存器约束: R2 = 0")
    print()
    result = verify_programs(prog_in, prog_out, reg_constraints)
    return result


@test("DIV_MOD_REWRITE")
def test_div_mod_rewrite():
    input_raw = [
        MOV_K(1, 100),
        MOV_K(2, 10),
        ALU(0x3, 1, 2),
        EXIT(),
    ]

    output_raw = [
        MOV_K(1, 100),
        MOV_K(2, 10),
        MOV(5, 2),
        ALU64_K(0x0, 5, 1),
        JMP_K(0x2, 5, 4, 1),
        JMP_K(0x1, 5, 1, 0),
        MOV_K(1, 0),
        NEG(1),
        JA(1),
        ALU(0x3, 1, 2),
        EXIT(),
    ]

    insns_in = parse_bytecode(input_raw)
    insns_out = parse_bytecode(output_raw)

    print("=== DIV 重写语义测试 ===")
    print("INPUT:")
    print(bytecode_to_str(insns_in))
    print("OUTPUT:")
    print(bytecode_to_str(insns_out))

    prog_in = BPFProgram(insns_in, "div_input")
    prog_out = BPFProgram(insns_out, "div_output")
    result = verify_programs(prog_in, prog_out, {})
    return result


@test("IDENTITY")
def test_identity():
    """空操作测试: 两个完全相同的简单程序"""
    raw = [
        MOV_K(0, 42),
        EXIT(),
    ]
    insns = parse_bytecode(raw)
    prog = BPFProgram(insns, "identity")
    result = verify_programs(prog, prog, {})
    return result


@test("UDIV32_ZERO_DIV")
def test_udiv32_zero_div():
    # Input: 原始程序 (C+asm)
    input_raw = [
        CALL(6000),          # call bpf_get_prandom_u32
        MOV32(1, 0),          # w1 = w0
        ALU_K(0x5, 1, 8),    # w1 &= 8
        ALU_K(0x6, 1, 1),    # w1 |= 1
        MOV_K(2, 0),         # w2 = 0
        JMP_K(0x5, 2, 2, 0), # if w2 != 0 goto +2
        ALU(0x7, 1, 1),      # w1 ^= w1  (R1 = 0)
        JA(1),               # goto +1 (跳过 DIV)
        ALU(0x3, 1, 2),      # w1 /= w2
        MOV_K(0, 0),         # r0 = 0
        EXIT(),
    ]

    # Output: Verifier 重写版本 (零除保护)
    output_raw = [
        CALL(6000),
        MOV32(1, 0),
        ALU_K(0x5, 1, 8),
        ALU_K(0x6, 1, 1),
        MOV_K(2, 0),
        JMP_K(0x5, 2, 2, 0), # if w2 != 0 goto +2
        MOV(5, 2),           # r5 = r2
        ALU64_K(0x0, 5, 1),  # r5 += 1
        JMP_K(0x2, 5, 4, 1), # if r5 >u 1 goto +4
        JMP_K(0x1, 5, 1, 0), # if r5 == 1 goto +1
        MOV_K(1, 0),         # r1 = 0
        NEG(1),              # r1 = -0 = 0
        JA(1),               # goto +1 (跳过 DIV)
        ALU(0x3, 1, 2),     # w1 /= w2
        MOV_K(0, 0),
        EXIT(),
    ]

    insns_in = parse_bytecode(input_raw)
    insns_out = parse_bytecode(output_raw)

    print("=== INPUT (C+asm) ===")
    print(bytecode_to_str(insns_in))
    print()
    print("=== OUTPUT (Verifier 重写) ===")
    print(bytecode_to_str(insns_out))

    prog_in = BPFProgram(insns_in, "input")
    prog_out = BPFProgram(insns_out, "output")
    return verify_programs(prog_in, prog_out, {})


@test("SIMPLE_ADD")
def test_simple_add():
    """简单加法测试"""
    input_raw = [
        MOV_K(1, 10),
        MOV_K(2, 20),
        ALU64(0x0, 0, 1),
        ALU64(0x0, 0, 2),
        EXIT(),
    ]
    output_raw = [
        MOV_K(1, 10),
        MOV_K(2, 20),
        ALU64_K(0x0, 0, 10),
        ALU64_K(0x0, 0, 20),
        EXIT(),
    ]
    insns_in = parse_bytecode(input_raw)
    insns_out = parse_bytecode(output_raw)
    print("=== 简单加法测试 ===")
    print("INPUT:")
    print(bytecode_to_str(insns_in))
    print("OUTPUT:")
    print(bytecode_to_str(insns_out))
    prog_in = BPFProgram(insns_in, "add_input")
    prog_out = BPFProgram(insns_out, "add_output")
    return verify_programs(prog_in, prog_out, {})
