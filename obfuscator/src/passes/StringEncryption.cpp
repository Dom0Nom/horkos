/*
 * obfuscator/src/passes/StringEncryption.cpp
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

} // namespace

PreservedAnalyses hk::StringEncryptionPass::run(Module &M,
                                                ModuleAnalysisManager &) {
    auto Annotated = hk::collectAnnotatedFunctions(M);
    if (Annotated.empty())
        return PreservedAnalyses::all();

    SmallPtrSet<GlobalVariable *, 32> Candidates;
    for (Function *F : Annotated)
        if (!F->isDeclaration())
            collectStrings(*F, Candidates);

    // Keep only strings used exclusively by annotated functions; a string shared
    // with a non-annotated reader would be read as ciphertext there.
    SmallPtrSet<GlobalVariable *, 32> Targets;
    for (GlobalVariable *GV : Candidates)
        if (usedOnlyInAnnotated(GV, Annotated))
            Targets.insert(GV);

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

    // Priority 0 = runs FIRST, before any other global constructor, so code
    // reachable from static init reads decrypted strings (65535 would run last).
    appendToGlobalCtors(M, Ctor, /*Priority=*/0);

    return PreservedAnalyses::none();
}
