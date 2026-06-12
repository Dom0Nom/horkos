# lit configuration for the Horkos obfuscation pass tests. Discovers
# *.test files and substitutes %opt (pinned llvm@19 opt) and %plugin (the built
# pass plugin). Run with:
#   LLVM19_BIN=$(brew --prefix llvm@19)/bin \
#     python3 -c "import lit.main; lit.main.main()" obfuscator/test -v

import os
import lit.formats

config.name = "HorkosObfuscator"
config.test_format = lit.formats.ShTest(execute_external=True)
config.suffixes = [".test"]
config.test_source_root = os.path.dirname(__file__)
config.test_exec_root = config.test_source_root

llvm_bin = os.environ.get("LLVM19_BIN", "/usr/local/opt/llvm@19/bin")
opt = os.path.join(llvm_bin, "opt")
filecheck = os.path.join(llvm_bin, "FileCheck")

# Plugin lives in ../build relative to this test dir. Allow .so or .dylib.
build_dir = os.path.normpath(os.path.join(config.test_source_root, "..", "build"))
plugin = None
for name in ("libHkObfuscator.so", "libHkObfuscator.dylib"):
    cand = os.path.join(build_dir, name)
    if os.path.exists(cand):
        plugin = cand
        break
if plugin is None:
    plugin = os.path.join(build_dir, "libHkObfuscator.so")  # default; build first

config.substitutions.append(("%opt", opt))
config.substitutions.append(("%plugin", plugin))
config.substitutions.append(("%FileCheck", filecheck))
