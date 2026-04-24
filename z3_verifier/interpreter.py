"""
BPF 程序解析、指令操作与指令构建辅助函数。
"""

from typing import Optional

from .opcode import decode_insn, BPF_EXIT, BPF_CALL


def parse_bytecode(raw: list) -> list:
    """将原始数字列表或 dict 列表解析为指令对象列表"""
    insns = []
    i = 0
    while i < len(raw):
        if isinstance(raw[i], dict):
            r = raw[i]
            insns.append(decode_insn(
                r.get("code", 0), r.get("dst", 0), r.get("src", 0),
                r.get("off", 0), r.get("imm", 0)
            ))
            if (r.get("code", 0) & 0x7) == 0 and (r.get("code", 0) >> 5) == 0:
                insns.append(decode_insn(0, 0, 0, 0, raw[i + 1]["imm"] if isinstance(raw[i + 1], dict) else raw[i + 1]))
                i += 1
        elif isinstance(raw[i], (list, tuple)):
            insns.append(decode_insn(raw[i][0], raw[i][1], raw[i][2], raw[i][3], raw[i][4]))
            if (raw[i][0] & 0x7) == 0 and (raw[i][0] >> 5) == 0:
                i += 1
                if i < len(raw):
                    insns.append(decode_insn(0, 0, 0, 0, raw[i][4] if isinstance(raw[i], (list, tuple)) else raw[i]))
        elif isinstance(raw[i], int):
            insns.append(decode_insn(raw[i], raw[i+1], raw[i+2], raw[i+3], raw[i+4]))
            if (raw[i] & 0x7) == 0 and (raw[i] >> 5) == 0:
                i += 5
                if i < len(raw):
                    insns.append(decode_insn(0, 0, 0, 0, raw[i] if isinstance(raw[i], int) else raw[i][4]))
            else:
                i += 5
            continue
        else:
            raise ValueError(f"Unknown bytecode format at index {i}: {type(raw[i])}")
        i += 1

    merged = []
    i = 0
    while i < len(insns):
        insn = insns[i]
        if (insn["code"] & 0x7) == 0 and (insn["code"] >> 5) == 0 and i + 1 < len(insns):
            merged.append({
                **insn,
                "imm_hi": insns[i + 1]["imm"],
                "combined_imm": ((insns[i + 1]["imm"] & 0xffffffff) << 32) | (insn["imm"] & 0xffffffff),
            })
            i += 2
        else:
            merged.append(insn)
            i += 1
    return merged


def bytecode_to_str(insns: list) -> str:
    """将指令列表转为可读的字符串"""
    lines = []
    for i, insn in enumerate(insns):
        code = insn["code"]
        cls_name = insn["class"]
        op_name = insn["op"]
        dst = insn["dst"]
        src = insn["src"]
        off = insn["off"]
        imm = insn["imm"]

        if code == BPF_EXIT:
            lines.append(f"  {i}: (90) EXIT")
        elif code == BPF_CALL:
            lines.append(f"  {i}: (85) CALL #{imm}")
        elif insn.get("combined_imm") is not None:
            lines.append(f"  {i}: ({code:02x}) LDDW R{dst} <- 0x{insn['combined_imm']:016x}")
        elif code == 0:
            lines.append(f"  {i}: (00) LDDW_PART2 imm={imm}")
        elif cls_name in ("JMP", "JMP32"):
            if src == 0:
                lines.append(f"  {i}: ({code:02x}) {cls_name:5s} {op_name:5s} R{dst}, #{imm}, off={off}")
            else:
                lines.append(f"  {i}: ({code:02x}) {cls_name:5s} {op_name:5s} R{dst}, R{src}, off={off}")
        elif cls_name in ("LD", "LDX", "ST", "STX"):
            size_char = {"B": 1, "H": 2, "W": 4, "DW": 8}.get(insn.get("size", ""), 0)
            if src == 0:
                lines.append(f"  {i}: ({code:02x}) {cls_name:5s} R{dst} <- [{src}+{off}], imm={imm}")
            else:
                lines.append(f"  {i}: ({code:02x}) {cls_name:5s} R{dst} <- [R{src}+{off}]")
        else:
            if src == 0:
                lines.append(f"  {i}: ({code:02x}) {cls_name:5s} {op_name:5s} R{dst} <- #{imm}")
            else:
                lines.append(f"  {i}: ({code:02x}) {cls_name:5s} {op_name:5s} R{dst} <- R{src}")
    return "\n".join(lines)


class BPFProgram:
    """一个 BPF 程序（指令列表 + 辅助信息）"""

    def __init__(self, insns: list, name: str = ""):
        self.insns = insns
        self.name = name
        self.len = len(insns)

    def __len__(self):
        return self.len

    def get(self, pc: int) -> Optional[dict]:
        if 0 <= pc < self.len:
            return self.insns[pc]
        return None


# ============================================================
# 指令构建辅助函数（用于测试用例）
# ============================================================

def _bpf(code, dst, src, off, imm):
    """构建 BPF 指令: (code, dst, src, off, imm)"""
    return (code, dst, src, off, imm)


def ALU64(op, dst, src): return _bpf(0x07 | (op << 4), dst, src, 0, 0)
def ALU64_K(op, dst, imm): return _bpf(0x07 | (op << 4), dst, 0, 0, imm)
def ALU(op, dst, src): return _bpf(0x00 | (op << 4), dst, src, 0, 0)
def ALU_K(op, dst, imm): return _bpf(0x00 | (op << 4), dst, 0, 0, imm)
def JMP(op, dst, src, off): return _bpf(0x05 | (op << 4), dst, src, off, 0)
def JMP_K(op, dst, off, imm): return _bpf(0x05 | (op << 4), dst, 0, off, imm)
def LDX(sz, dst, src, off): return _bpf(0x01 | (sz << 3), dst, src, off, 0)
def STX(sz, dst, src, off): return _bpf(0x03 | (sz << 3), dst, src, off, 0)
def ST(sz, dst, off, imm): return _bpf(0x02 | (sz << 3), dst, 0, off, imm)
def LDDW(dst, imm_hi, imm_lo): return [_bpf(0x18, dst, 0, 0, imm_lo), (0, 0, 0, 0, imm_hi)]
def MOV(dst, src): return _bpf(0x07 | (0xb << 4), dst, src, 0, 0)
def MOV_K(dst, imm): return _bpf(0x07 | (0xb << 4), dst, 0, 0, imm)
def MOV32(dst, src): return _bpf(0x00 | (0xb << 4), dst, src, 0, 0)
def MOV32_K(dst, imm): return _bpf(0x00 | (0xb << 4), dst, 0, 0, imm)
def EXIT(): return _bpf(0x90, 0, 0, 0, 0)
def CALL(imm): return _bpf(0x85, 0, 0, 0, imm)
def NEG(dst): return _bpf(0x07 | (0xc << 4), dst, 0, 0, 0)
def NEG32(dst): return _bpf(0x00 | (0xc << 4), dst, 0, 0, 0)
def JA(off): return _bpf(0x05 | (0x0 << 4), 0, 0, off, 0)
