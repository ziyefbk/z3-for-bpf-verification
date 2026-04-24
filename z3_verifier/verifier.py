"""
Z3 符号执行验证器。

给定两个 BPF 程序（原始 bytecode 和 verifier 输出的 bytecode），
在相同的初始状态下，验证两者是否产生相同的 R0（返回值）。
"""

from z3 import *

from .interpreter import BPFProgram
from .semantics import alu32, alu64, jmp_cond
from .opcode import BPF_EXIT, BPF_CALL


def verify_programs(prog_in: BPFProgram, prog_out: BPFProgram,
                    reg_constraints: dict = None) -> dict:
    """对两个 BPF 程序做符号执行，验证 exit 时 R0 相等。"""
    solver = Solver()
    solver.set(timeout=30000)

    n_in = len(prog_in)
    n_out = len(prog_out)
    max_n = max(n_in, n_out)

    init_r = []
    for i in range(11):
        if reg_constraints and i in reg_constraints:
            c = reg_constraints[i]
            if isinstance(c, int):
                init_r.append(BitVecVal(c, 64))
                solver.add(BitVec(f"R{i}_init", 64) == c)
            else:
                init_r.append(c)
        else:
            init_r.append(BitVec(f"R{i}_init", 64))

    R_in = {}
    R_out = {}

    for pc in range(max_n):
        for r in range(11):
            R_in[(pc, r)] = BitVec(f"rin_{pc}_{r}", 64)
            R_out[(pc, r)] = BitVec(f"rout_{pc}_{r}", 64)

    for r in range(11):
        solver.add(R_in[(0, r)] == init_r[r])
        solver.add(R_out[(0, r)] == init_r[r])

    AX_in = BitVecVal(0, 64)
    AX_out = BitVecVal(0, 64)

    def _model_prog(prog, R, AX):
        visited = set()
        queue = [0]

        while queue:
            cur_pc = queue.pop()
            if cur_pc in visited or cur_pc >= max_n:
                continue
            visited.add(cur_pc)

            insn = prog.get(cur_pc)
            if insn is None:
                continue

            code = insn["code"]
            cls = code & 0x7
            op = (code >> 4) & 0xf
            off = insn["off"]
            imm = insn["imm"]
            dst_i = insn["dst"]
            src_i = insn["src"]

            regs_cur = {r: R[(cur_pc, r)] for r in range(11)}

            if code == BPF_EXIT:
                continue

            if code == BPF_CALL:
                new_regs = dict(regs_cur)
                new_regs[0] = BitVecVal(0, 64)
                for r in range(11):
                    solver.add(R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r]))
                queue.append(cur_pc + 1)
                continue

            if cls in (5, 6):
                if src_i == 0:
                    src_v = BitVecVal(imm, 64)
                else:
                    src_v = regs_cur.get(src_i, BitVecVal(0, 64))
                dst_v = regs_cur.get(dst_i, BitVecVal(0, 64))
                cond = jmp_cond(op, dst_v, src_v)
                target = cur_pc + 1 + off
                fallthrough = cur_pc + 1
                for next_pc in (target, fallthrough):
                    if 0 <= next_pc < max_n:
                        new_regs = dict(regs_cur)
                        for r in range(11):
                            solver.add(R[(next_pc, r)] == new_regs.get(r, regs_cur[r]))
                        queue.append(next_pc)
                continue

            if cls in (1, 2, 3):
                new_regs = dict(regs_cur)
                for r in range(11):
                    solver.add(R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r]))
                queue.append(cur_pc + 1)
                continue

            if (code & 0x7) == 0 and (code >> 5) == 0:
                new_regs = dict(regs_cur)
                combined = insn.get("combined_imm", imm)
                new_regs[dst_i] = BitVecVal(combined, 64)
                for r in range(11):
                    solver.add(R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r]))
                queue.append(cur_pc + 1)
                continue

            is_alu64 = (cls == 7)
            if src_i == 0:
                src_v = BitVecVal(imm, 64)
            else:
                src_v = regs_cur.get(src_i, BitVecVal(0, 64))
            dst_v = regs_cur.get(dst_i, BitVecVal(0, 64))
            is_signed = (off == 1)
            if is_alu64:
                new_dst, _ = alu64(op, dst_v, src_v, AX, off, is_signed)
            else:
                new_dst, _ = alu32(op, dst_v, src_v, AX, off, is_signed)
            new_regs = dict(regs_cur)
            new_regs[dst_i] = simplify(new_dst)
            for r in range(11):
                solver.add(R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r]))
            queue.append(cur_pc + 1)

    _model_prog(prog_in, R_in, AX_in)
    _model_prog(prog_out, R_out, AX_out)

    exit_in = None
    exit_out = None
    for i in range(n_in):
        if prog_in.get(i) and prog_in.get(i)["code"] == BPF_EXIT:
            exit_in = i
            break
    for i in range(n_out):
        if prog_out.get(i) and prog_out.get(i)["code"] == BPF_EXIT:
            exit_out = i
            break

    if exit_in is None or exit_out is None:
        return {
            "status": "unknown",
            "reason": f"EXIT 未找到: in={exit_in}, out={exit_out}",
            "n_in": n_in, "n_out": n_out,
        }

    r0_in_final = R_in[(exit_in, 0)]
    r0_out_final = R_out[(exit_out, 0)]

    solver.push()
    solver.add(r0_in_final != r0_out_final)
    result = solver.check()
    if result == sat:
        model = solver.model()
        ce = {str(d): model[d] for d in model.decls() if "init" in str(d)}
        return {
            "status": "not_equivalent",
            "counterexample": ce,
            "reason": "找到使两边 R0 不同的初始状态",
        }
    elif result == unsat:
        return {
            "status": "equivalent",
            "reason": "在所有初始状态下 R0 恒相等 (UNSAT)",
            "exit_in": exit_in,
            "exit_out": exit_out,
        }
    else:
        return {
            "status": "unknown",
            "reason": f"Z3 返回 {result} (可能超时)",
        }
