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

    # 调试：打印 bytecode 顺序和 JMP 目标解析
    def _debug_prog(prog, label):
        print(f"\n[DEBUG] === {label} bytecode order ===")
        for i in range(len(prog)):
            insn = prog.get(i)
            if insn is None:
                continue
            code = insn["code"]
            cls = code & 0x7
            off = insn["off"]
            imm = insn["imm"]
            dst_i = insn["dst"]
            src_i = insn["src"]
            op = (code >> 4) & 0xf
            if cls in (5, 6):
                target = i + 1 + off
                fallthrough = i + 1
                src_desc = f"imm={imm}" if src_i == 0 else f"R{src_i}"
                print(f"  pc={i:2d}: code=0x{code:02x} cls={cls} op={op} "
                      f"dst=R{dst_i} src={src_desc} off={off} "
                      f"-> target=pc{target} fallthrough=pc{fallthrough}")
            elif code == BPF_CALL:
                print(f"  pc={i:2d}: code=0x{code:02x} CALL imm={imm}")
            elif code == BPF_EXIT:
                print(f"  pc={i:2d}: code=0x{code:02x} EXIT")
            else:
                print(f"  pc={i:2d}: code=0x{code:02x} cls={cls} op={op} dst=R{dst_i} src=R{src_i} imm={imm}")

    _debug_prog(prog_in, "INPUT")
    _debug_prog(prog_out, "OUTPUT")

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

    shared_mem = K(BitVecSort(64), BitVec("shared_mem_init", 8))
    Mem_in_arr = {"mem": shared_mem}
    Mem_out_arr = {"mem": shared_mem}

    AX_in = BitVecVal(0, 64)
    AX_out = BitVecVal(0, 64)

    def _load_bytes(mem_holder, addr, n_bytes):
        parts = []
        for i in range(n_bytes):
            byte_addr = simplify(addr + i) if isinstance(addr, BitVecRef) else addr + i
            parts.append(Select(mem_holder["mem"], byte_addr))
        result = Concat(parts) if len(parts) > 1 else parts[0]
        return ZeroExt(64 - len(parts) * 8, result)

    def _store_bytes(mem_holder, addr, value, n_bytes):
        m = mem_holder["mem"]
        for i in range(n_bytes):
            byte_addr = simplify(addr + i) if isinstance(addr, BitVecRef) else addr + i
            byte_val = Extract(7, 0, LShr(value, i * 8)) if isinstance(value, BitVecRef) else ((value >> (i * 8)) & 0xFF)
            m = Store(m, byte_addr, byte_val)
        mem_holder["mem"] = m

    def _check_reachable(path_cond):
        """检查当前路径条件下是否可满足（不修改 solver）"""
        check_solver = Solver()
        check_solver.set(timeout=30000)
        # 复制现有断言
        for a in solver.assertions():
            check_solver.add(a)
        check_solver.add(path_cond)
        return check_solver.check() == sat

    def _model_prog(prog, R, AX, mem_holder):
        visited = {}   # pc -> set of path condition string hashes
        queue = [(0, BoolVal(True))]
        reached_exits = []   # 实际到达的 EXIT pc 列表

        while queue:
            cur_pc, path_cond = queue.pop()
            cond_str = str(simplify(path_cond))
            if cond_str in visited.get(cur_pc, set()):
                continue
            visited.setdefault(cur_pc, set()).add(cond_str)

            if cur_pc >= max_n:
                continue

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
            size_mode = (code >> 3) & 0x3

            regs_cur = {r: R[(cur_pc, r)] for r in range(11)}

            if code == BPF_EXIT:
                reached_exits.append((cur_pc, path_cond))
                continue

            if code == BPF_CALL:
                new_regs = dict(regs_cur)
                imm_val = insn.get("imm", 0)
                prefix = prog.name
                if imm_val == 6000:
                    rnd = ZeroExt(32, BitVec(f'user_rnd_{prefix}_pc{cur_pc}', 32))
                    new_regs[0] = rnd
                elif imm_val == 7:
                    rnd = BitVec(f'ktime_{prefix}_pc{cur_pc}', 64)
                    new_regs[0] = rnd
                elif imm_val == 27:
                    rnd = ZeroExt(32, BitVec(f'prnd_{prefix}_pc{cur_pc}', 32))
                    new_regs[0] = rnd
                else:
                    rnd = BitVec(f'call_{prefix}_{imm_val}_pc{cur_pc}', 64)
                    new_regs[0] = rnd
                for r in range(11):
                    solver.add(Implies(path_cond, R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r])))
                queue.append((cur_pc + 1, path_cond))
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

                for next_pc, branch_cond in [(target, cond), (fallthrough, Not(cond))]:
                    if not (0 <= next_pc < max_n):
                        continue
                    reachable_path = And(path_cond, branch_cond)
                    reachable = _check_reachable(reachable_path)
                    print(f"[TRACE] pc={cur_pc} prog={prog.name}: "
                          f"{'TAKEN' if next_pc == target else 'FALLTHROUGH'} "
                          f"-> pc={next_pc} reachable={reachable} "
                          f"path_cond={simplify(path_cond)} branch_cond={simplify(branch_cond)}")
                    if not reachable:
                        continue
                    new_regs = dict(regs_cur)
                    for r in range(11):
                        solver.add(Implies(reachable_path, R[(next_pc, r)] == new_regs.get(r, regs_cur[r])))
                    queue.append((next_pc, reachable_path))
                continue

            if cls == 1:
                src_v = regs_cur.get(src_i, BitVecVal(0, 64))
                addr = src_v + off
                size_map = {0: 1, 1: 2, 2: 4, 3: 8}
                n_bytes = size_map.get(size_mode, 8)
                loaded = _load_bytes(mem_holder, addr, n_bytes)
                new_regs = dict(regs_cur)
                new_regs[dst_i] = loaded
                for r in range(11):
                    solver.add(Implies(path_cond, R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r])))
                queue.append((cur_pc + 1, path_cond))
                continue

            if cls == 3:
                dst_v = regs_cur.get(dst_i, BitVecVal(0, 64))
                src_v = regs_cur.get(src_i, BitVecVal(0, 64))
                addr = dst_v + off
                size_map = {0: 1, 1: 2, 2: 4, 3: 8}
                n_bytes = size_map.get(size_mode, 8)
                _store_bytes(mem_holder, addr, src_v, n_bytes)
                new_regs = dict(regs_cur)
                for r in range(11):
                    solver.add(Implies(path_cond, R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r])))
                queue.append((cur_pc + 1, path_cond))
                continue

            if cls == 2:
                dst_v = regs_cur.get(dst_i, BitVecVal(0, 64))
                addr = dst_v + off
                size_map = {0: 1, 1: 2, 2: 4, 3: 8}
                n_bytes = size_map.get(size_mode, 8)
                store_val = BitVecVal(imm & ((1 << (n_bytes * 8)) - 1), n_bytes * 8)
                _store_bytes(mem_holder, addr, store_val, n_bytes)
                new_regs = dict(regs_cur)
                for r in range(11):
                    solver.add(Implies(path_cond, R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r])))
                queue.append((cur_pc + 1, path_cond))
                continue

            if (code & 0x7) == 0 and (code >> 5) == 0:
                new_regs = dict(regs_cur)
                combined = insn.get("combined_imm", imm)
                new_regs[dst_i] = BitVecVal(combined, 64)
                for r in range(11):
                    solver.add(Implies(path_cond, R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r])))
                queue.append((cur_pc + 1, path_cond))
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
            # 调试：打印每条指令后的寄存器值
            new_regs = dict(regs_cur)
            if cls in (0, 7) and op not in (0xc,):
                new_regs[dst_i] = simplify(new_dst)
            reg_snapshot = {r: simplify(new_regs.get(r, regs_cur.get(r, BitVecVal(0, 64)))) for r in range(4)}
            print(f"[STEP] pc={cur_pc} prog={prog.name} code=0x{code:02x}: R={reg_snapshot}")

            new_regs = dict(regs_cur)
            new_regs[dst_i] = simplify(new_dst)
            for r in range(11):
                solver.add(Implies(path_cond, R[(cur_pc + 1, r)] == new_regs.get(r, regs_cur[r])))
            queue.append((cur_pc + 1, path_cond))

        return reached_exits

    reached_exits_in = _model_prog(prog_in, R_in, AX_in, Mem_in_arr)
    reached_exits_out = _model_prog(prog_out, R_out, AX_out, Mem_out_arr)

    exit_ins = sorted(set(pc for pc, _ in reached_exits_in))
    exit_outs = sorted(set(pc for pc, _ in reached_exits_out))

    if not exit_ins or not exit_outs:
        return {
            "status": "unknown",
            "reason": f"无可达 EXIT: in={exit_ins}, out={exit_outs}",
            "n_in": n_in, "n_out": n_out,
        }

    # 调试：打印每个可达 exit point 的 R0 在约束下的具体值
    eval_solver = Solver()
    eval_solver.set(timeout=30000)
    for a in solver.assertions():
        eval_solver.add(a)
    if eval_solver.check() == sat:
        m = eval_solver.model()
        for exit_in in exit_ins:
            print(f"[DEBUG] INPUT  pc={exit_in}: R0 = {m.eval(R_in[(exit_in, 0)])}")
        for exit_out in exit_outs:
            print(f"[DEBUG] OUTPUT pc={exit_out}: R0 = {m.eval(R_out[(exit_out, 0)])}")

    for exit_in in exit_ins:
        for exit_out in exit_outs:
            r0_in_final = R_in[(exit_in, 0)]
            r0_out_final = R_out[(exit_out, 0)]
            solver.push()
            solver.add(r0_in_final != r0_out_final)
            result = solver.check()
            print(f"[DEBUG] check R_in[{exit_in}] != R_out[{exit_out}]: {result}")
            if result == sat:
                model = solver.model()
                ce = {str(d): model[d] for d in model.decls() if "init" in str(d)}
                return {
                    "status": "not_equivalent",
                    "counterexample": ce,
                    "reason": f"exit_in=pc{exit_in}, exit_out=pc{exit_out}: 找到使两边 R0 不同的初始状态",
                    "exit_in": exit_in,
                    "exit_out": exit_out,
                }

    return {
        "status": "equivalent",
        "reason": f"在所有初始状态下 R0 恒相等 (UNSAT), 检查了 in{exit_ins} x out{exit_outs}",
        "exit_ins": exit_ins,
        "exit_outs": exit_outs,
    }
