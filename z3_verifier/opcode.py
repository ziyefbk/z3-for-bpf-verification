"""
操作码定义与指令解码。

与 include/uapi/linux/bpf.h 保持对齐。
"""

# 类 (class = code & 7)
BPF_CLASS = {
    0: "LD",    # 0b000: 包含 ALU(0x04-0x0f) 和 LD_ABS/LD_IND/LD_DW(0x18等)
    1: "LDX",   # 0b001
    2: "ST",    # 0b010
    3: "STX",   # 0b011
    4: "ALD",   # 0b100 (旧版 ALU，用于 32-bit ALU)
    5: "JMP",   # 0b101
    6: "JMP32", # 0b110
    7: "ALU64", # 0b111
}

# ALU/JMP 操作码 (op = code >> 4)
BPF_OP = {
    0x0: "ADD",
    0x1: "SUB",
    0x2: "MUL",
    0x3: "DIV",
    0x4: "MOD",
    0x5: "AND",
    0x6: "OR",
    0x7: "XOR",
    0x8: "LSH",
    0x9: "RSH",
    0xa: "ARSH",
    0xb: "MOV",
    0xc: "NEG",
    0xd: "END",
}

# 大小修饰符 (size = code >> 3 & 3)
BPF_SIZE = {
    0: "B",   # 0b00
    1: "H",   # 0b01
    2: "W",   # 0b10
    3: "DW",  # 0b11
}

# JMP 条件
BPF_JMP = {
    0x0: "JA",    # always jump
    0x1: "JEQ",   # ==
    0x2: "JGT",   # unsigned >
    0x3: "JGE",   # unsigned >=
    0x4: "JSET",  # bitwise &
    0x5: "JNE",   # !=
    0x6: "JSGT",  # signed >
    0x7: "JSGE",  # signed >=
    0x8: "JLT",   # unsigned <
    0x9: "JLE",   # unsigned <=
    0xa: "JSLT",  # signed <
    0xb: "JSLE",  # signed <=
    0xc: "JCOND", # conditional pseudo
}

BPF_EXIT = 0x90
BPF_CALL = 0x80


def _get_cls(code: int) -> str:
    """根据 opcode 精细判断指令类别"""
    cls = code & 0x7
    if cls == 0:
        if code == 0x18 or code == 0x00:
            return "LD"
        return "ALU"
    elif cls == 1:
        return "LDX"
    elif cls == 2:
        return "ST"
    elif cls == 3:
        return "STX"
    elif cls == 4:
        return "ALD"
    elif cls == 5:
        return "JMP"
    elif cls == 6:
        return "JMP32"
    elif cls == 7:
        return "ALU64"
    return f"?({cls})"


def decode_insn(code: int, dst: int, src: int, off: int, imm: int) -> dict:
    """将 BPF 指令的原始字段解码为可读的 dict"""
    cls = code & 0x7
    op = (code >> 4) & 0xf
    size = (code >> 3) & 0x3

    cls_name = _get_cls(code)
    if code & 0x7 in (5, 6):
        op_name = BPF_JMP.get(op, f"?({op})")
    else:
        op_name = BPF_OP.get(op, f"?({op})")

    return {
        "code": code,
        "class": cls_name,
        "op": op_name,
        "dst": dst,
        "src": src,
        "off": off,
        "imm": imm,
        "raw": (code, dst, src, off, imm),
    }
