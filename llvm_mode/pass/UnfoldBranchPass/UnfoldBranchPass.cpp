/*
  Make optimization fail for branches
  e.g
  if (x == 1 & y == 1) {}
  =>
  if (x==1) {
    if (y == 1) {}
  }
 */

#include <llvm/IR/Attributes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
using namespace llvm;

namespace {

class UnfoldBranch : public FunctionPass {
private:
  Type *VoidTy;
  IntegerType *Int8Ty;
  IntegerType *Int32Ty;

  FunctionCallee UnfoldBranchFn;

public:
  static char ID;

  UnfoldBranch() : FunctionPass(ID) {}

  bool doInitialization(Module &M) override;
  bool runOnFunction(Function &F) override;
};

} // namespace

char UnfoldBranch::ID = 0;

bool UnfoldBranch::doInitialization(Module &M) {

  LLVMContext &C = M.getContext();

  Int8Ty = IntegerType::getInt8Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);
  VoidTy = Type::getVoidTy(C);

  srandom(1851655);

  Type *UnfoldBranchArgs[1] = {Int32Ty};
  FunctionType *UnfoldBranchFnTy =
      FunctionType::get(VoidTy, UnfoldBranchArgs, /*isVarArg=*/false);

  AttributeList AL;
  AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                       Attribute::NoUnwind);

  UnfoldBranchFn =
      M.getOrInsertFunction("__unfold_branch_fn", UnfoldBranchFnTy, AL);

  return true;
}

bool UnfoldBranch::runOnFunction(Function &F) {
#ifndef ENABLE_UNFOLD_BRANCH
  return false;
#endif

  if (F.isDeclaration())
    return false;

  LLVMContext &C = F.getContext();

  SmallSet<BasicBlock *, 20> VisitedBBs;
  for (auto &BB : F) {
    Instruction *Inst = BB.getTerminator();

    if (BranchInst *BI = dyn_cast<BranchInst>(Inst)) {
      if (BI->isUnconditional() || BI->getNumSuccessors() < 2)
        continue;

      Value *Cond = BI->getCondition();
      if (!Cond)
        continue;

      for (auto *Successor : BI->successors()) {
        if (VisitedBBs.contains(Successor)) {
          continue;
        }
        VisitedBBs.insert(Successor);

        IRBuilder<> IRB(Successor, Successor->getFirstInsertionPt());

        unsigned int CurLoc = rand() % 1048576;
        CallInst *Call =
            IRB.CreateCall(UnfoldBranchFn, {ConstantInt::get(Int32Ty, CurLoc)});
        Call->setMetadata(C.getMDKindID("unfold"), MDNode::get(C, None));
      }
    }
  }

  return true;
}

static void registerUnfoldBranchPass(const PassManagerBuilder &,
                                     legacy::PassManagerBase &PM) {
  PM.add(new UnfoldBranch());
}

static RegisterPass<UnfoldBranch>
    RegisterUnfoldBranch("unfold-branch", "Prevent optimization of conditions");

static RegisterStandardPasses
    RegisterUnfoldBranchEarlyAsPossible(PassManagerBuilder::EP_EarlyAsPossible,
                                        registerUnfoldBranchPass);

static RegisterStandardPasses RegisterUnfoldBranchEnabledOnOptLevel0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerUnfoldBranchPass);
