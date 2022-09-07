#include "llvm/ADT/Statistic.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

#include <cstdint>
#include <iterator>
#include <llvm/ADT/Hashing.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Intrinsics.h>

#define DEBUG_TYPE "stack-mapper"

using namespace llvm;

STATISTIC(injectedStackMaps, "Number of injected stackmaps");

namespace {
class StackMapper : public FunctionPass {
  const static std::uint32_t NumShadowBytes;

  hash_code ModuleHash;

public:
  static char ID;

  StackMapper() : FunctionPass(ID) {}

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.setPreservesCFG();
  }

  bool doInitialization(Module &M) override;

  bool runOnFunction(Function &F) override;
};
} // namespace

char StackMapper::ID = 0;
const std::uint32_t StackMapper::NumShadowBytes = 0;

bool StackMapper::doInitialization(Module &M) {
  ModuleHash = hash_value(M.getSourceFileName());
  return false;
}

bool StackMapper::runOnFunction(Function &F) {
  LLVM_DEBUG(dbgs() << "Instrumenting function: " << F.getName() << '\n');
  auto FunctionHash = hash_combine(hash_value(F.getName()), ModuleHash);

  LLVM_DEBUG(dbgs() << "Found allocas:\n");
  DenseMap<BasicBlock *, SmallVector<AllocaInst *, 0>> BBsToAllocas;
  for (auto &BB : F) {
    for (auto &Inst : BB) {
      if (auto *CurrentAlloca = dyn_cast<AllocaInst>(&Inst)) {
        LLVM_DEBUG(dbgs() << *CurrentAlloca << "\n");
        BBsToAllocas[&BB].push_back(CurrentAlloca);
      }
    }
  }

  std::size_t RecordIdx = 0;
  for (auto &KVPair : BBsToAllocas) {
    // Insert the stackmap for this basic block after the last alloca in it
    auto Allocas = KVPair.second;
    IRBuilder<> IRB(Allocas.back()->getNextNonDebugInstruction());

    auto RecordID = hash_combine(hash_value(RecordIdx), FunctionHash);

    SmallVector<Value *, 10> StackMapArgs;
    StackMapArgs.push_back(IRB.getInt64(RecordID));
    StackMapArgs.push_back(IRB.getInt32(NumShadowBytes));

    for (auto &Alloca : Allocas) {
      auto &DL = F.getParent()->getDataLayout();

      auto AllocationSize = Alloca->getAllocationSizeInBits(DL);
      if (!AllocationSize) {
        LLVM_DEBUG(dbgs() << "Unsupported VLA encountered, ignoring.\n");
        continue;
      }

      auto *AllocationSizeValue = IRB.getInt64(AllocationSize.getValue() / 8);
      StackMapArgs.push_back(Alloca);
      StackMapArgs.push_back(AllocationSizeValue);
    }

    IRB.CreateIntrinsic(Intrinsic::experimental_stackmap, {}, StackMapArgs);
    ++injectedStackMaps;
    ++RecordIdx;
  }

  return true;
}

static RegisterPass<StackMapper>
    RegisterStackMapper("stack-mapper",
                        "Insert stackmaps for all stack allocations");

static void registerStackMapperCompilerPass(const PassManagerBuilder &,
                                            legacy::PassManagerBase &PM) {
  PM.add(new StackMapper());
}

static RegisterStandardPasses RegisterBBTaintTracerOptimizerLast{
    PassManagerBuilder::EP_OptimizerLast, registerStackMapperCompilerPass};

static RegisterStandardPasses RegisterBBTaintTracerEnabledOnOptLevel0{
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerStackMapperCompilerPass};