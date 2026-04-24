"""
Z3 BPF Validator 命令行入口。
"""

import sys
import json
import argparse
import traceback

from .interpreter import parse_bytecode, bytecode_to_str, BPFProgram
from .verifier import verify_programs
from .tests import TESTS


def main():
    parser = argparse.ArgumentParser(description="Z3 BPF Validator")
    parser.add_argument("input", nargs="?", help="输入 bytecode 文件 (JSON)")
    parser.add_argument("output", nargs="?", help="输出 bytecode 文件 (JSON)")
    parser.add_argument("--regs", help="寄存器约束，格式: R0=0,R1=1,...")
    parser.add_argument("--test", choices=list(TESTS.keys()), help="运行内置测试")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    args = parser.parse_args()

    if args.test:
        print(f"\n{'='*60}")
        print(f"  运行测试: {args.test}")
        print(f"{'='*60}\n")
        test_fn = TESTS[args.test]
        try:
            result = test_fn()
            print(f"\n结果: {result}")
            if result.get("status") == "equivalent":
                print("PASS: 两个程序语义等价")
                return 0
            elif result.get("status") == "not_equivalent":
                print("FAIL: 两个程序语义不等价")
                if result.get("counterexample"):
                    print(f"  反例: {result['counterexample']}")
                return 1
            else:
                print(f"? {result.get('reason', 'unknown')}")
                return 2
        except Exception as e:
            print(f"ERROR: 测试失败: {e}")
            traceback.print_exc()
            return 3

    if args.input and args.output:
        with open(args.input) as f:
            input_raw = json.load(f)
        with open(args.output) as f:
            output_raw = json.load(f)

        insns_in = parse_bytecode(input_raw)
        insns_out = parse_bytecode(output_raw)

        print(f"Input:  {len(insns_in)} 条指令")
        print(f"Output: {len(insns_out)} 条指令")
        print()
        print("=== INPUT ===")
        print(bytecode_to_str(insns_in))
        print()
        print("=== OUTPUT ===")
        print(bytecode_to_str(insns_out))

        reg_constraints = {}
        if args.regs:
            for item in args.regs.split(","):
                k, v = item.split("=")
                reg_constraints[int(k[1:])] = int(v)

        prog_in = BPFProgram(insns_in, "input")
        prog_out = BPFProgram(insns_out, "output")
        result = verify_programs(prog_in, prog_out, reg_constraints)
        print(f"\n验证结果: {result}")
        return 0

    print("用法: python validator.py --test TEST_NAME")
    print(f"可用测试: {list(TESTS.keys())}")
    print()
    print("运行所有内置测试...\n")

    passed = 0
    failed = 0
    unknown = 0

    for name in TESTS:
        print(f"\n{'='*60}")
        print(f"  {name}")
        print(f"{'='*60}")
        try:
            result = TESTS[name]()
            status = result.get("status", "unknown")
            if status == "equivalent":
                print(f"PASS: {result.get('reason', '等价')}")
                passed += 1
            elif status == "not_equivalent":
                print(f"FAIL: {result.get('reason', '不等价')}")
                if result.get("counterexample"):
                    print(f"  反例: {result['counterexample']}")
                failed += 1
            else:
                print(f"? {result.get('reason', 'unknown')}")
                unknown += 1
        except Exception as e:
            print(f"ERROR: {e}")
            traceback.print_exc()
            failed += 1

    print(f"\n\n总计: {passed} 通过, {failed} 失败, {unknown} 未知")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
