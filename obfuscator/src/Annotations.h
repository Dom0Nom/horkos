/*
 * obfuscator/src/Annotations.h
 * Role: Collects the set of functions opted into obfuscation via
 *       __attribute__((annotate("hk_obfuscate"))). Clang lowers function-level
 *       annotate attributes into the module-global @llvm.global.annotations
 *       array, NOT into a function attribute the new PM can read directly — so a
 *       pass MUST walk that global. A pass that queries function attributes for
 *       the annotation silently no-ops against valid input (guardrail in the
 *       Phase 5 plan, Step 5.2). This header is the single place that walk lives.
 * Target: build-time LLVM-19 tool only. Never shipped.
 */

#pragma once

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringRef.h"

namespace hk {

/// The annotation string a symbol must carry to be obfuscated.
inline constexpr llvm::StringRef kObfuscateTag = "hk_obfuscate";

/// Returns the set of Functions in M annotated with "hk_obfuscate".
/// Walks @llvm.global.annotations: an array of
///   { i8* fn, i8* annotationStr, i8* file, i32 line, i8* args }.
inline llvm::SmallPtrSet<llvm::Function *, 16>
collectAnnotatedFunctions(llvm::Module &M) {
    using namespace llvm;
    SmallPtrSet<Function *, 16> Result;

    GlobalVariable *GA = M.getGlobalVariable("llvm.global.annotations");
    if (!GA || !GA->hasInitializer())
        return Result;

    auto *Arr = dyn_cast<ConstantArray>(GA->getInitializer());
    if (!Arr)
        return Result;

    for (Use &Op : Arr->operands()) {
        auto *Entry = dyn_cast<ConstantStruct>(Op.get());
        if (!Entry || Entry->getNumOperands() < 2)
            continue;

        // Operand 0: the annotated value, possibly behind a bitcast. In opaque-
        // pointer IR (LLVM 19 default) there is no bitcast and it is the Function
        // directly.
        Function *Fn = dyn_cast<Function>(Entry->getOperand(0)->stripPointerCasts());
        if (!Fn)
            continue;

        // Operand 1: pointer to the annotation string global.
        auto *StrGV = dyn_cast<GlobalVariable>(
            Entry->getOperand(1)->stripPointerCasts());
        if (!StrGV || !StrGV->hasInitializer())
            continue;

        auto *Str = dyn_cast<ConstantDataArray>(StrGV->getInitializer());
        if (!Str || !Str->isCString())
            continue;

        if (Str->getAsCString() == kObfuscateTag)
            Result.insert(Fn);
    }

    return Result;
}

} // namespace hk
