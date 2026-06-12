/*
 * Role: Declares the three Horkos LLVM-19 obfuscation passes (new pass manager).
 *       All are module passes so they can read @llvm.global.annotations once and
 *       transform only the opted-in functions/globals.
 * Target: build-time LLVM-19 tool only. Never shipped (Locked Decision #5).
 */

#pragma once

#include "llvm/IR/PassManager.h"

namespace hk {

/// Control-flow flattening: collapses a function's CFG into a switch dispatcher.
/// Opt-in via __attribute__((annotate("hk_obfuscate"))).
struct ControlFlowFlatteningPass
    : llvm::PassInfoMixin<ControlFlowFlatteningPass> {
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
};

/// Opaque predicates: guards branches with always-true arithmetic invariants so
/// static analysis cannot prune the bogus side. Opt-in.
struct OpaquePredicatesPass : llvm::PassInfoMixin<OpaquePredicatesPass> {
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
};

/// String encryption: XOR-encrypts opted-in private string globals at build time
/// and injects a load-time constructor that decrypts them. Opt-in.
struct StringEncryptionPass : llvm::PassInfoMixin<StringEncryptionPass> {
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &);
};

} // namespace hk
