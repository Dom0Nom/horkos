/*
 * Role: Guards each conditional branch in an opted-in function with an
 *       always-true opaque predicate (x*(x+1) is always even), ANDed into the
 *       original condition so semantics are preserved but the bogus-looking
 *       arithmetic resists static branch pruning. Opt-in via
 *       __attribute__((annotate("hk_obfuscate"))) — non-annotated functions are
 *       left untouched.
 * Target: LLVM-19 new pass manager, build-time tool only.
 */

#include "Passes.h"
#include "Annotations.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/SmallVector.h"

using namespace llvm;

PreservedAnalyses hk::OpaquePredicatesPass::run(Module &M,
                                                ModuleAnalysisManager &) {
    auto Annotated = hk::collectAnnotatedFunctions(M);
    if (Annotated.empty())
        return PreservedAnalyses::all();

    LLVMContext &Ctx = M.getContext();
    IntegerType *I32 = Type::getInt32Ty(Ctx);

    // A volatile-loaded seed the optimizer cannot constant-fold, so the
    // always-true predicate survives later passes. Created lazily on the first
    // conditional branch we actually rewrite, so a no-op run does not mutate the
    // module while reporting PreservedAnalyses::all().
    GlobalVariable *Seed = M.getGlobalVariable("hk_opaque_seed");

    bool Changed = false;
    for (Function *F : Annotated) {
        if (F->isDeclaration())
            continue;

        SmallVector<BranchInst *, 16> CondBranches;
        for (BasicBlock &BB : *F)
            if (auto *BI = dyn_cast<BranchInst>(BB.getTerminator()))
                if (BI->isConditional())
                    CondBranches.push_back(BI);

        for (BranchInst *BI : CondBranches) {
            if (!Seed) {
                Seed = new GlobalVariable(M, I32, /*isConstant=*/false,
                                          GlobalValue::InternalLinkage,
                                          ConstantInt::get(I32, 0),
                                          "hk_opaque_seed");
            }
            IRBuilder<> B(BI);
            Value *X = B.CreateLoad(I32, Seed, /*isVolatile=*/true, "hk_op_x");
            // x*(x+1) is always even -> (t & 1) == 0 is always true.
            Value *Xp1 = B.CreateAdd(X, ConstantInt::get(I32, 1));
            Value *T = B.CreateMul(X, Xp1);
            Value *Low = B.CreateAnd(T, ConstantInt::get(I32, 1));
            Value *OpaqueTrue =
                B.CreateICmpEQ(Low, ConstantInt::get(I32, 0), "hk_op_true");
            Value *NewCond =
                B.CreateAnd(BI->getCondition(), OpaqueTrue, "hk_op_cond");
            BI->setCondition(NewCond);
            Changed = true;
        }
    }

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
