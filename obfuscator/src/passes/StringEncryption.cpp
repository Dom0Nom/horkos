/*
 * Role: XOR-encrypts the private C-string globals referenced by opted-in
 *       functions at build time, marks them writable, and injects a load-time
 *       constructor (llvm.global_ctors) that decrypts them in place before main.
 *       Opt-in: only strings reachable from an hk_obfuscate-annotated function
 *       are touched.
 * Target: LLVM-19 new pass manager, build-time tool only.
 */

#include "Passes.h"
#include "Annotations.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Transforms/Utils/ModuleUtils.h" // appendToGlobalCtors

#include <vector>

using namespace llvm;

namespace {

// Returns true if GV is a private/internal constant C-string we can encrypt.
bool isEncryptableString(GlobalVariable &GV) {
    if (!GV.hasInitializer() || !GV.isConstant())
        return false;
    if (!GV.hasPrivateLinkage() && !GV.hasInternalLinkage())
        return false;
    auto *CDA = dyn_cast<ConstantDataArray>(GV.getInitializer());
    return CDA && CDA->isCString();
}

// Collects the encryptable string globals referenced anywhere in F.
void collectStrings(Function &F, SmallPtrSetImpl<GlobalVariable *> &Out) {
    for (BasicBlock &BB : F)
        for (Instruction &I : BB)
            for (Use &Op : I.operands())
                if (auto *GV = dyn_cast<GlobalVariable>(
                        Op.get()->stripPointerCasts()))
                    if (isEncryptableString(*GV))
                        Out.insert(GV);
}

// True iff every use of GV resolves to an instruction inside an annotated
// function. A string shared with a non-annotated function (or referenced from
// another global's initializer) must NOT be encrypted: that reader would see
// ciphertext at runtime since only annotated code expects the decrypt ctor.
bool usedOnlyInAnnotated(GlobalVariable *GV,
                         const SmallPtrSetImpl<Function *> &Annotated) {
    SmallVector<User *, 16> Work(GV->user_begin(), GV->user_end());
    SmallPtrSet<User *, 16> Seen;
    while (!Work.empty()) {
        User *U = Work.pop_back_val();
        if (!Seen.insert(U).second)
            continue;
        if (auto *I = dyn_cast<Instruction>(U)) {
            Function *F = I->getFunction();
            if (!F || !Annotated.count(F))
                return false;
        } else if (isa<GlobalValue>(U)) {
            // Referenced from another global (e.g. an initializer) — cannot
            // guarantee it is read only after the decrypt ctor. Be safe.
            return false;
        } else if (isa<Constant>(U)) {
            // ConstantExpr (GEP/bitcast): descend to its users.
            for (User *UU : U->users())
                Work.push_back(UU);
        } else {
            return false; // unknown user kind — do not encrypt.
        }
    }
    return true;
}

// Collects every function transitively reachable from all global constructors
// registered in llvm.global_ctors, excluding hk_strdec itself (which we are
// about to register). Indirect calls are conservatively treated as reaching
// every function in the module — the returned set is therefore a superset (safe
// to skip encryption when a string's user appears here, wasteful but not wrong).
SmallPtrSet<Function *, 32> collectCtorReachableFunctions(Module &M) {
    SmallPtrSet<Function *, 32> Reachable;
    SmallVector<Function *, 16> Work;

    GlobalVariable *CtorList = M.getNamedGlobal("llvm.global_ctors");
    if (!CtorList || !CtorList->hasInitializer())
        return Reachable;

    auto *CA = dyn_cast<ConstantArray>(CtorList->getInitializer());
    if (!CA)
        return Reachable;

    bool HasIndirect = false;
    for (unsigned I = 0, E = CA->getNumOperands(); I < E; ++I) {
        auto *Entry = dyn_cast<ConstantStruct>(CA->getOperand(I));
        if (!Entry)
            continue;
        // Struct layout: { i32 priority, ptr fn, ptr data }
        auto *Fn = dyn_cast<Function>(Entry->getOperand(1)->stripPointerCasts());
        if (!Fn || Fn->isDeclaration())
            continue;
        if (Reachable.insert(Fn).second)
            Work.push_back(Fn);
    }

    while (!Work.empty()) {
        Function *F = Work.pop_back_val();
        for (BasicBlock &BB : *F) {
            for (Instruction &I : BB) {
                auto *CB = dyn_cast<CallBase>(&I);
                if (!CB)
                    continue;
                Function *Callee = CB->getCalledFunction();
                if (!Callee) {
                    // Indirect call — conservatively mark every function.
                    HasIndirect = true;
                    goto done;
                }
                if (!Callee->isDeclaration() && Reachable.insert(Callee).second)
                    Work.push_back(Callee);
            }
        }
    }
done:
    if (HasIndirect) {
        // Treat every non-declaration as potentially reachable from a ctor.
        Reachable.clear();
        for (Function &F : M)
            if (!F.isDeclaration())
                Reachable.insert(&F);
    }
    return Reachable;
}

} // namespace

PreservedAnalyses hk::StringEncryptionPass::run(Module &M,
                                                ModuleAnalysisManager &) {
    auto Annotated = hk::collectAnnotatedFunctions(M);
    if (Annotated.empty())
        return PreservedAnalyses::all();

    // Collect functions reachable from any global constructor (conservative).
    // A string used by such a function must NOT be encrypted: the ctor may run
    // before hk_strdec (same priority-0 ctor slot, link-order-defined) and would
    // read ciphertext. This check is skipped for hk_strdec itself, which we have
    // not yet registered and which is the only annotated ctor we control.
    SmallPtrSet<Function *, 32> CtorReachable = collectCtorReachableFunctions(M);

    SmallPtrSet<GlobalVariable *, 32> Candidates;
    for (Function *F : Annotated)
        if (!F->isDeclaration())
            collectStrings(*F, Candidates);

    // Keep only strings used exclusively by annotated functions AND not reachable
    // from any global constructor. A string shared with a non-annotated reader, or
    // reachable from a ctor that could run before hk_strdec, would be read as
    // ciphertext by that reader.
    SmallPtrSet<GlobalVariable *, 32> Targets;
    for (GlobalVariable *GV : Candidates) {
        if (!usedOnlyInAnnotated(GV, Annotated))
            continue;
        // Reject if any annotated user is also reachable from a ctor.
        bool CtorExposed = false;
        for (User *U : GV->users()) {
            SmallVector<User *, 8> UWork;
            UWork.push_back(U);
            SmallPtrSet<User *, 8> Seen;
            while (!UWork.empty() && !CtorExposed) {
                User *CU = UWork.pop_back_val();
                if (!Seen.insert(CU).second)
                    continue;
                if (auto *I = dyn_cast<Instruction>(CU)) {
                    Function *F = I->getFunction();
                    if (F && CtorReachable.count(F))
                        CtorExposed = true;
                } else if (isa<Constant>(CU)) {
                    for (User *UU : CU->users())
                        UWork.push_back(UU);
                }
            }
        }
        if (!CtorExposed)
            Targets.insert(GV);
    }

    if (Targets.empty())
        return PreservedAnalyses::all();

    LLVMContext &Ctx = M.getContext();
    IntegerType *I8 = Type::getInt8Ty(Ctx);
    IntegerType *I32 = Type::getInt32Ty(Ctx);
    const uint8_t Key = 0x5A;

    struct Encrypted {
        GlobalVariable *GV;
        uint32_t Len;
    };
    std::vector<Encrypted> Done;

    for (GlobalVariable *GV : Targets) {
        auto *CDA = cast<ConstantDataArray>(GV->getInitializer());
        StringRef Data = CDA->getRawDataValues(); // includes the NUL terminator
        std::vector<uint8_t> Enc(Data.begin(), Data.end());
        for (uint8_t &B : Enc)
            B ^= Key;

        Constant *NewInit = ConstantDataArray::get(Ctx, ArrayRef<uint8_t>(Enc));
        GV->setInitializer(NewInit);
        GV->setConstant(false); // must be writable to decrypt at load time
        Done.push_back({GV, (uint32_t)Enc.size()});
    }

    // Build the decrypt constructor: void hk_strdec() { for each GV: xor bytes }.
    FunctionType *CtorTy = FunctionType::get(Type::getVoidTy(Ctx), false);
    Function *Ctor = Function::Create(CtorTy, GlobalValue::InternalLinkage,
                                      "hk_strdec", &M);
    BasicBlock *Entry = BasicBlock::Create(Ctx, "entry", Ctor);
    IRBuilder<> B(Entry);

    for (const Encrypted &E : Done) {
        // Decrypt byte-by-byte with a straight-line unrolled XOR; simple and
        // verifier-trivial for the typically-short literals.
        for (uint32_t i = 0; i < E.Len; ++i) {
            Value *Ptr = B.CreateInBoundsGEP(
                E.GV->getValueType(), E.GV,
                {ConstantInt::get(I32, 0), ConstantInt::get(I32, i)});
            /* Volatile so a later optimizer (LTO/globalopt) cannot statically
             * evaluate the store-only ctor, fold the XOR back into the global
             * initializer, and restore the plaintext. */
            Value *Cur = B.CreateLoad(I8, Ptr, /*isVolatile=*/true);
            Value *Dec = B.CreateXor(Cur, ConstantInt::get(I8, Key));
            B.CreateStore(Dec, Ptr, /*isVolatile=*/true);
        }
    }
    B.CreateRetVoid();

    // Priority 0 is the LOWEST numeric priority. The C++ standard guarantees that
    // constructors with a lower priority value run before those with a higher value,
    // but it gives NO ordering guarantee between constructors at the SAME priority.
    // A third-party or compiler-emitted ctor also registered at priority 0 may run
    // before hk_strdec in link order — any string reachable from such a ctor (even
    // transitively through an annotated function it happens to call) would be read
    // as ciphertext. The ctor-reachability guard above rejects those cases.
    appendToGlobalCtors(M, Ctor, /*Priority=*/0);

    return PreservedAnalyses::none();
}
