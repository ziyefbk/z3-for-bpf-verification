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


@test("UDIV32_ZERO_DIV")
def test_udiv32_zero_div():
    input_raw = [
        CALL(6000),              # 0: (85) call bpf_user_rnd_u32#6000
        MOV32(1, 0),              # 1: (bc) w1 = w0
        ALU_K(0x5, 1, 8),         # 2: (54) w1 &= 8
        ALU_K(0x6, 1, 1),         # 3: (44) w1 |= 1
        MOV_K(2, 0),              # 4: (b4) w2 = 0
        JMP_K(0x5, 2, 1, 0),     # 5: (56) if w2 != 0x0 goto pc+2
        ALU(0x7, 1, 1),           # 6: (a4) w1 ^= w1
        JA(0),                    # 7: (05) goto pc+1
        ALU(0x3, 1, 2),          # 8: (3c) w1 /= w2
        MOV_K(0, 0),              # 9: (b7) r0 = 0
        EXIT(),                   # 10: (95) exit
    ]

    output_raw = [
        CALL(6000),              # 0: (85) call bpf_user_rnd_u32#6000
        MOV32(1, 0),              # 1: (bc) w1 = w0
        ALU_K(0x5, 1, 8),         # 2: (54) w1 &= 8
        ALU_K(0x6, 1, 1),         # 3: (44) w1 |= 1
        MOV_K(2, 0),              # 4: (b4) w2 = 0
        ALU(0x3, 1, 2),           # 5: (3c) w1 /= w2
        JMP_K(0x5, 1, 2, 0),
        MOV_K(0, 0),
        EXIT(),
        LDX(3, 0, 1, 0),
        EXIT(),
    ]

    insns_in = parse_bytecode(input_raw)
    insns_out = parse_bytecode(output_raw)

    print("=== INPUT ===")
    print(bytecode_to_str(insns_in))
    print("=== OUTPUT ===")
    print(bytecode_to_str(insns_out))

    prog_in = BPFProgram(insns_in, "input")
    prog_out = BPFProgram(insns_out, "output")
    result = verify_programs(prog_in, prog_out, {})
    print("=== RESULT ===")
    print(result)
    return result
