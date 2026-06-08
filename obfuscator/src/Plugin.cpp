/*
 * obfuscator/src/Plugin.cpp
 * Role: Registers the three Horkos obfuscation passes with the LLVM-19 new pass
 *       manager so `opt -load-pass-plugin=... -passes=hk-cff,hk-opaque,hk-strenc`
 *       and the bundled lit tests can drive them. Build-time tool only.
 * Target: LLVM-19. Never shipped (Locked Decision #5).
 */

#include "Passes.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

static void registerCallbacks(PassBuilder &PB) {
    PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM,
           ArrayRef<PassBuilder::PipelineElement>) -> bool {
            if (Name == "hk-cff") {
                MPM.addPass(hk::ControlFlowFlatteningPass());
                return true;
            }
            if (Name == "hk-opaque") {
                MPM.addPass(hk::OpaquePredicatesPass());
                return true;
            }
            if (Name == "hk-strenc") {
                MPM.addPass(hk::StringEncryptionPass());
                return true;
            }
            return false;
        });
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "HkObfuscator", "0.1", registerCallbacks};
}
