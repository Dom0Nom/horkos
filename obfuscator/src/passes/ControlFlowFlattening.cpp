/*
 * obfuscator/src/passes/ControlFlowFlattening.cpp
 * Role: Flattens the control-flow graph of an opted-in function into a single
 *       switch dispatcher driven by a state variable, so the original block
 *       order is not recoverable from the CFG. SSA correctness is guaranteed by
 *       first demoting all registers and PHIs to stack slots (reg2mem), after
 *       which the transform is a pure CFG rewrite. Opt-in via
 *       __attribute__((annotate("hk_obfuscate"))); non-annotated functions are
 *       left byte-for-byte unchanged.
 * Target: LLVM-19 new pass manager, build-time tool only.
 */

#include "Passes.h"
#include "Annotations.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Transforms/Utils/Local.h" // DemoteRegToStack, DemotePHIToStack

#include <vector>

using namespace llvm;

namespace {

// We only flatten functions whose terminators we know how to rewrite. Bail on
// EH, indirect/computed branches, and switches (conservative but always-correct).
bool canFlatten(Function &F) {
    for (BasicBlock &BB : F) {
        Instruction *T = BB.getTerminator();
        if (isa<InvokeInst>(T) || isa<IndirectBrInst>(T) ||
            isa<CallBrInst>(T) || isa<SwitchInst>(T))
            return false;
        // Exceptional terminators we will not rewrite.
        if (isa<ResumeInst>(T) || isa<CatchSwitchInst>(T) ||
            isa<CatchReturnInst>(T) || isa<CleanupReturnInst>(T))
            return false;
    }
    return true;
}

// reg2mem: push every cross-block SSA value and every PHI onto the stack so the
// flattening cannot break dominance.
void demoteToStack(Function &F) {
    std::vector<PHINode *> Phis;
    for (BasicBlock &BB : F)
        for (Instruction &I : BB)
            if (auto *PN = dyn_cast<PHINode>(&I))
                Phis.push_back(PN);
    for (PHINode *PN : Phis)
        DemotePHIToStack(PN);

    std::vector<Instruction *> Cross;
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (isa<AllocaInst>(&I))
                continue;
            for (User *U : I.users()) {
                auto *UI = dyn_cast<Instruction>(U);
                if (UI && UI->getParent() != &BB) {
                    Cross.push_back(&I);
                    break;
                }
            }
        }
    }
    for (Instruction *I : Cross)
        DemoteRegToStack(*I);
}

bool flatten(Function &F) {
    if (F.isDeclaration())
        return false;
    if (!canFlatten(F))
        return false;

    // Need at least an entry plus one more block to be worth flattening.
    if (F.size() < 2)
        return false;

    demoteToStack(F);

    LLVMContext &Ctx = F.getContext();
    IntegerType *I32 = Type::getInt32Ty(Ctx);
    BasicBlock *Entry = &F.getEntryBlock();

    // Pool = every block except the entry. Every branch target lives here (the
    // entry has no predecessors in valid IR), so each pool block gets a state id.
    SmallVector<BasicBlock *, 32> Pool;
    for (BasicBlock &BB : F)
        if (&BB != Entry)
            Pool.push_back(&BB);
    if (Pool.empty())
        return false;

    DenseMap<BasicBlock *, uint32_t> Id;
    for (uint32_t I = 0; I < Pool.size(); ++I)
        Id[Pool[I]] = I;

    // State variable, allocated at the very top of the entry block.
    IRBuilder<> EB(&*Entry->getFirstInsertionPt());
    AllocaInst *StateVar = EB.CreateAlloca(I32, nullptr, "hk_cff_state");

    // Dispatcher: load state, switch to the matching block.
    BasicBlock *Dispatch = BasicBlock::Create(Ctx, "hk_cff_dispatch", &F, Pool[0]);
    BasicBlock *DefaultBB =
        BasicBlock::Create(Ctx, "hk_cff_default", &F, Pool[0]);
    {
        IRBuilder<> DB(DefaultBB);
        DB.CreateUnreachable();
    }
    IRBuilder<> DSB(Dispatch);
    LoadInst *Cur = DSB.CreateLoad(I32, StateVar, "hk_cff_cur");
    SwitchInst *Sw = DSB.CreateSwitch(Cur, DefaultBB, Pool.size());
    for (BasicBlock *BB : Pool)
        Sw->addCase(ConstantInt::get(I32, Id[BB]), BB);

    // Rewrite a block's terminator to route through the dispatcher.
    auto reroute = [&](BasicBlock *BB) {
        Instruction *T = BB->getTerminator();
        auto *BI = dyn_cast<BranchInst>(T);
        if (!BI) {
            // ReturnInst and UnreachableInst are intentional direct exits of the
            // flattened region. A ReturnInst must leave the function immediately
            // (routing it back through the dispatcher would change semantics);
            // UnreachableInst has no successor to rewrite. Both are left in place
            // — the flattened function still exits correctly, and the CFG is
            // opaque for all intra-function edges that do have BranchInst
            // terminators. canFlatten() above has already excluded all other
            // non-branch terminator kinds (invoke, indirectbr, etc.).
            return;
        }

        IRBuilder<> B(BI);
        if (BI->isUnconditional()) {
            BasicBlock *Succ = BI->getSuccessor(0);
            B.CreateStore(ConstantInt::get(I32, Id[Succ]), StateVar);
        } else {
            BasicBlock *T0 = BI->getSuccessor(0);
            BasicBlock *T1 = BI->getSuccessor(1);
            Value *Next = B.CreateSelect(BI->getCondition(),
                                         ConstantInt::get(I32, Id[T0]),
                                         ConstantInt::get(I32, Id[T1]));
            B.CreateStore(Next, StateVar);
        }
        B.CreateBr(Dispatch);
        BI->eraseFromParent();
    };

    reroute(Entry);
    for (BasicBlock *BB : Pool)
        reroute(BB);

    return true;
}

} // namespace

PreservedAnalyses hk::ControlFlowFlatteningPass::run(Module &M,
                                                     ModuleAnalysisManager &) {
    auto Annotated = hk::collectAnnotatedFunctions(M);
    if (Annotated.empty())
        return PreservedAnalyses::all();

    bool Changed = false;
    for (Function *F : Annotated)
        Changed |= flatten(*F);

    return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
