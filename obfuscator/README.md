# Horkos Obfuscator (LLVM 19)

A standalone, build-time LLVM-19 pass plugin. **Never shipped to end users**
(Locked Decision #5) — it transforms the AC/DRM binaries during the build and
is then discarded.

## Passes

| Pass name | Effect | Opt-in |
|-----------|--------|--------|
| `hk-cff` | Control-flow flattening: collapses the CFG into a switch dispatcher (reg2mem first, so SSA stays valid) | per-function |
| `hk-opaque` | Opaque predicates: ANDs an always-true `x*(x+1)` invariant into each conditional branch | per-function |
| `hk-strenc` | String encryption: XOR-encrypts opted-in private string globals at build time, injects a load-time decrypt constructor | per-string (reachable from an opted-in function) |

## Opt-in (guardrail #9)

Passes only transform functions carrying
`__attribute__((annotate("hk_obfuscate")))`. Clang lowers that attribute into
the module-global `@llvm.global.annotations` array (not a function attribute the
new PM can read), so the plugin walks that global — see `src/Annotations.h`. The
GAME binary's hot-loop functions never carry the annotation; only
init/licence/integrity/attestation symbols do. The AC binary may be obfuscated
broadly via a sweeping driver that annotates everything.

## Build

```
cmake -S obfuscator -B obfuscator/build \
      -DLLVM_DIR=$(brew --prefix llvm@19)/lib/cmake/llvm
cmake --build obfuscator/build
```

Produces `obfuscator/build/libHkObfuscator.so`.

## Use

```
opt -load-pass-plugin=obfuscator/build/libHkObfuscator.so \
    -passes='hk-strenc,hk-opaque,hk-cff' input.ll -S -o obfuscated.ll
```

Order `hk-strenc` before the CFG passes so it sees the original string uses.
