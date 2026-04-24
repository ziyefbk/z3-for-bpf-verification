# Z3 BPF Validator

基于 SMT 的 eBPF Verifier 语义等价性验证工具。

## 依赖

- Python 3.10+
- z3-solver (`pip install z3-solver`)

## 使用方法

```bash
python validator.py <input_bytecode.json> <output_bytecode.json> [--regs R0=R0_val,R1=R1_val,...]
```

或直接运行内置测试：

```bash
python validator.py --test UDIV32
```
