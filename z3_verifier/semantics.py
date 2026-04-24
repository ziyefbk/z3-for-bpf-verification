"""
ALU 语义与跳转条件计算。
"""

from z3 import *


def alu32(op: int, dst: BitVecRef, src: BitVecRef,
          ax: BitVecRef, off: int, is_signed: bool) -> tuple:
    """
    32-bit ALU 操作语义，返回 (new_dst, new_ax)。
    off=0: unsigned, off=1: signed
    """
    dst32 = ZeroExt(32, Extract(31, 0, dst))
    src32 = ZeroExt(32, Extract(31, 0, src))
    ax32 = ZeroExt(32, Extract(31, 0, ax))

    if op == 0x0:
        result = ZeroExt(32, Extract(31, 0, dst32 + src32))
        return result, ax
    elif op == 0x1:
        result = ZeroExt(32, Extract(31, 0, dst32 - src32))
        return result, ax
    elif op == 0x2:
        result = ZeroExt(32, Extract(31, 0, (dst32 * src32)))
        return result, ax
    elif op == 0x3:
        if not is_signed:
            cond = src32 == BitVecVal(0, 64)
            result = If(cond, BitVecVal(0, 64),
                        ZeroExt(32, UDiv(Extract(31, 0, dst32), Extract(31, 0, src32))))
            return result, ax
        else:
            s_dst = SignExt(32, Extract(31, 0, dst32))
            s_src = SignExt(32, Extract(31, 0, src32))
            abs_dst = If(s_dst < BitVecVal(0, 128), -s_dst, s_dst)
            abs_src = If(s_src < BitVecVal(0, 128), -s_src, s_src)
            cond = src32 == BitVecVal(0, 64)
            ax_val = If(cond, BitVecVal(0, 128),
                       If(SDiv(abs_dst, abs_src) >= BitVecVal(0, 128),
                          SDiv(abs_dst, abs_src), BitVecVal(0, 128)))
            result = If(cond, BitVecVal(0, 64),
                       If((s_dst < 0) != (s_src < 0),
                          ZeroExt(32, Extract(31, 0, -ax_val)),
                          ZeroExt(32, Extract(31, 0, ax_val))))
            return result, ax
    elif op == 0x4:
        if not is_signed:
            cond = src32 == BitVecVal(0, 64)
            result = If(cond, ZeroExt(32, Extract(31, 0, dst32)),
                       ZeroExt(32, URem(Extract(31, 0, dst32), Extract(31, 0, src32))))
            return result, ax
        else:
            s_dst = SignExt(32, Extract(31, 0, dst32))
            s_src = SignExt(32, Extract(31, 0, src32))
            cond = src32 == BitVecVal(0, 64)
            abs_dst = If(s_dst < BitVecVal(0, 128), -s_dst, s_dst)
            abs_src = If(s_src < BitVecVal(0, 128), -s_src, s_src)
            ax_val = If(cond, BitVecVal(0, 128),
                       If(SDiv(abs_dst, abs_src) >= BitVecVal(0, 128),
                          SRem(abs_dst, abs_src), BitVecVal(0, 128)))
            result = If(cond, ZeroExt(32, Extract(31, 0, dst32)),
                       If(s_dst < 0,
                          ZeroExt(32, Extract(31, 0, -ax_val)),
                          ZeroExt(32, Extract(31, 0, ax_val))))
            return result, ax
    elif op == 0x5:
        result = ZeroExt(32, Extract(31, 0, dst32) & Extract(31, 0, src32))
        return result, ax
    elif op == 0x6:
        result = ZeroExt(32, Extract(31, 0, dst32) | Extract(31, 0, src32))
        return result, ax
    elif op == 0x7:
        result = ZeroExt(32, Extract(31, 0, dst32) ^ Extract(31, 0, src32))
        return result, ax
    elif op == 0x8:
        shamt = Extract(31, 0, src32) & BitVecVal(31, 32)
        result = ZeroExt(32, Extract(31, 0, dst32) << shamt)
        return result, ax
    elif op == 0x9:
        shamt = Extract(31, 0, src32) & BitVecVal(31, 32)
        result = ZeroExt(32, LShr(Extract(31, 0, dst32), shamt))
        return result, ax
    elif op == 0xa:
        shamt = Extract(31, 0, src32) & BitVecVal(31, 32)
        result = ZeroExt(32, Ashr(Extract(31, 0, dst32), shamt))
        return result, ax
    elif op == 0xb:
        return src32, ax
    elif op == 0xc:
        result = ZeroExt(32, -Extract(31, 0, dst32))
        return result, ax
    return dst, ax


def alu64(op: int, dst: BitVecRef, src: BitVecRef,
          ax: BitVecRef, off: int, is_signed: bool) -> tuple:
    """64-bit ALU 操作语义"""
    if op == 0x0:
        return dst + src, ax
    elif op == 0x1:
        return dst - src, ax
    elif op == 0x2:
        return dst * src, ax
    elif op == 0x3:
        if not is_signed:
            cond = src == BitVecVal(0, 64)
            result = If(cond, BitVecVal(0, 64), UDiv(dst, src))
            return result, ax
        else:
            cond = src == BitVecVal(0, 64)
            result = If(cond, BitVecVal(0, 64), SDiv(dst, src))
            return result, ax
    elif op == 0x4:
        if not is_signed:
            cond = src == BitVecVal(0, 64)
            rem = URem(dst, src)
            result = If(cond, BitVecVal(0, 64), rem)
            return result, ax
        else:
            cond = src == BitVecVal(0, 64)
            rem = If(dst < 0, -SRem(-dst, src), SRem(dst, src))
            result = If(cond, BitVecVal(0, 64), rem)
            return result, ax
    elif op == 0x5:
        return dst & src, ax
    elif op == 0x6:
        return dst | src, ax
    elif op == 0x7:
        return dst ^ src, ax
    elif op == 0x8:
        shamt = src & BitVecVal(63, 64)
        return dst << shamt, ax
    elif op == 0x9:
        shamt = src & BitVecVal(63, 64)
        return LShr(dst, shamt), ax
    elif op == 0xa:
        shamt = src & BitVecVal(63, 64)
        return dst >> shamt, ax
    elif op == 0xb:
        return src, ax
    elif op == 0xc:
        return -dst, ax
    return dst, ax


def jmp_cond(op: int, dst: BitVecRef, src: BitVecRef) -> BoolRef:
    """计算 BPF 跳转条件"""
    if op == 0x0:
        return BoolVal(True)
    elif op == 0x1:
        return dst == src
    elif op == 0x2:
        return UGT(dst, src)
    elif op == 0x3:
        return UGE(dst, src)
    elif op == 0x4:
        return (dst & src) != BitVecVal(0, 64)
    elif op == 0x5:
        return dst != src
    elif op == 0x6:
        return dst > src
    elif op == 0x7:
        return dst >= src
    elif op == 0x8:
        return ULT(dst, src)
    elif op == 0x9:
        return ULE(dst, src)
    elif op == 0xa:
        return dst < src
    elif op == 0xb:
        return dst <= src
    return BoolVal(False)
