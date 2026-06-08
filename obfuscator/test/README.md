# Obfuscator test fixtures

`fixtures/fixture.ll` is generated from `fixtures/fixture.c` with the **pinned
llvm@19 clang**. LLVM IR text format drifts between major versions, so the
regeneration toolchain is non-negotiable — always regenerate with llvm@19:

```
$(brew --prefix llvm@19)/bin/clang -emit-llvm -S -O0 -fno-discard-value-names \
    obfuscator/test/fixtures/fixture.c -o obfuscator/test/fixtures/fixture.ll
```

`fixture.c` has two functions on purpose:
- `secret` — annotated `hk_obfuscate`; has a branch (CFF + opaque) and a string
  literal (string encryption).
- `plain` — not annotated; every pass must leave it unchanged. The `CHECK-NOT`
  lines in the `.test` files prove opt-in actually gates the transform.

Run the suite:

```
cmake --build obfuscator/build
LLVM19_BIN=$(brew --prefix llvm@19)/bin \
  python3 -c "import lit.main; lit.main.main()" obfuscator/test -v
```
