#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <fstream>
#include <random>

#include "abilist.h"
#include "defs.h"

#define DEBUG_TYPE "angora-pass"

using namespace llvm;
// only do taint tracking, used to compile third-party libraries.
static cl::opt<bool> DFSanMode("DFSanMode", cl::desc("dfsan mode"), cl::Hidden);

static cl::opt<bool> TrackMode("TrackMode", cl::desc("track mode"), cl::Hidden);

static cl::list<std::string> ClABIListFiles(
    "angora-dfsan-abilist",
    cl::desc("file listing native abi functions and how the pass treats them"),
    cl::Hidden);

static cl::list<std::string> ClExploitListFiles(
    "angora-exploitation-list",
    cl::desc("file listing functions and instructions to exploit"), cl::Hidden);

namespace {

#define MAX_EXPLOIT_CATEGORY 5
const char *ExploitCategoryAll = "all";
const char *ExploitCategory[] = {"i0", "i1", "i2", "i3", "i4"};
const char *CompareFuncCat = "cmpfn";

// Compute a hash based on the name and the size of the current module.
hash_code computeModuleHash(const std::string &Filename) {
  auto Hash = hash_value(Filename);

  std::ifstream ModuleFile(Filename,
                           std::ifstream::ate | std::ifstream::binary);
  auto FileSize = ModuleFile.tellg();
  if (FileSize != -1) {
    Hash = hash_combine(Hash, hash_value(static_cast<std::size_t>(FileSize)));
  }

  return Hash;
}

class AngoraLLVMPass : public ModulePass {
public:
  static char ID;
  bool FastMode = false;
  uint32_t SerialInstIDCounter;
  hash_code ModuleHash;
  std::default_random_engine SharedRandomEngine;
  std::default_random_engine FastRandomEngine;
  std::uniform_int_distribution<std::uint32_t> InstructionIdDistrib;
  std::uniform_int_distribution<std::uint32_t> ContextIdDistrib;
  std::uniform_int_distribution<std::uint32_t> BasicBlockIdDistrib;
  std::uniform_int_distribution<std::uint32_t> PercentDistrib;
  unsigned long int RandSeed = 1;
  bool IsBitcode;
  unsigned int InstRatio = 100;

  // Const Variables
  DenseSet<uint32_t> UniqCidSet;

  // Configurations
  bool GenerateIDsRandomly;
  int NumFnContext;

  MDNode *ColdCallWeights;

  // Types
  Type *VoidTy;
  IntegerType *Int1Ty;
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  Type *Int8PtrTy;
  Type *Int64PtrTy;

  // Global vars
  GlobalVariable *AngoraMapPtr;
  GlobalVariable *AngoraPrevLoc;
  GlobalVariable *AngoraContext;
  GlobalVariable *AngoraCondId;
  GlobalVariable *AngoraCallSite;

  FunctionCallee TraceCmp;
  FunctionCallee TraceSw;
  FunctionCallee TraceCmpTT;
  FunctionCallee TraceSwTT;
  FunctionCallee TraceFnTT;
  FunctionCallee TraceExploitTT;

  FunctionType *TraceCmpTy;
  FunctionType *TraceSwTy;
  FunctionType *TraceCmpTtTy;
  FunctionType *TraceSwTtTy;
  FunctionType *TraceFnTtTy;
  FunctionType *TraceExploitTtTy;

  // Custom setting
  AngoraABIList ABIList;
  AngoraABIList ExploitList;

  // Meta
  unsigned NoSanMetaId;
  MDTuple *NoneMetaNode;

  AngoraLLVMPass()
      : ModulePass(ID), ContextIdDistrib(0, MAP_SIZE),
        BasicBlockIdDistrib(0, MAP_SIZE), PercentDistrib(0, 100) {}
  bool runOnModule(Module &M) override;
  uint32_t getInstructionId(Instruction *Inst);
  uint32_t getRandomBasicBlockId();
  bool skipBasicBlock();
  void reseedRandNumGenerators(uint32_t Seed);
  uint32_t getRandomContextId();
  uint32_t getRandomInstructionId();
  void setValueNonSan(Value *V);
  void setInsNonSan(Instruction *Inst);
  Value *castArgType(IRBuilder<> &IRB, Value *V);
  void initVariables(Module &M);
  void addEdgeInstrumentation(Module &M, BasicBlock &BB);
  void visitCallInst(CallInst *CI);
  void visitInvokeInst(InvokeInst *II);
  void visitCompareFunc(CallBase *CB);
  void visitBranchInst(BranchInst *BI);
  void visitCmpInst(CmpInst *CI);
  void processCmp(CmpInst *Cmp, Constant *Cid, Instruction *InsertPoint);
  void processBoolCmp(Value *Cond, Constant *Cid, Instruction *InsertPoint);
  void visitSwitchInst(Module &M, SwitchInst *SI);
  void visitExploitation(Instruction *Inst);
  void processCall(CallBase *CB);
  void addFnWrap(Function &F);
};

} // namespace

char AngoraLLVMPass::ID = 0;

void AngoraLLVMPass::reseedRandNumGenerators(uint32_t Seed) {
  LLVM_DEBUG(dbgs() << "Random generators seeded with: " << Seed << "\n");

  // The SharedRandomEngine is shared between the "track" and the "fast"
  // instrumentation, while the FastRandomEngine is used only in the "fast"
  // instrumentation. In order to preserve ID consistency, the two need to be
  // kept separate so that, with the same seeds, "track" and "fast"
  // instrumentations will receive the same IDs for context IDs and instruction
  // IDs.
  SharedRandomEngine.seed(Seed);
  FastRandomEngine.seed(Seed);
}

bool AngoraLLVMPass::skipBasicBlock() {
  assert(FastMode);
  return PercentDistrib(FastRandomEngine) >= InstRatio;
}

uint32_t AngoraLLVMPass::getRandomBasicBlockId() {
  assert(FastMode);
  return BasicBlockIdDistrib(FastRandomEngine);
}

uint32_t AngoraLLVMPass::getRandomContextId() {
  return ContextIdDistrib(SharedRandomEngine);
}

uint32_t AngoraLLVMPass::getRandomInstructionId() {
  return InstructionIdDistrib(SharedRandomEngine);
}

uint32_t AngoraLLVMPass::getInstructionId(Instruction *Inst) {
  uint32_t Hash = 0;
  if (IsBitcode) {
    Hash = ++SerialInstIDCounter;
  } else {
    if (GenerateIDsRandomly) {
      Hash = getRandomInstructionId();
    } else {
      if (DILocation *Loc = Inst->getDebugLoc()) {
        auto Line = Loc->getLine();
        auto Col = Loc->getColumn();
        Hash = hash_combine(hash_value(Line), hash_value(Col),
                            hash_value(ModuleHash));
        LLVM_DEBUG(dbgs() << "[LOC] " << Loc->getScope()->getFilename()
                          << ", Ln " << Line << ", Col " << Col << "\n");
      } else {
        Hash = getRandomInstructionId();
        LLVM_DEBUG(
            dbgs()
            << "Missing debug info, random instruction ID used instead.\n");
      }
    }

    while (UniqCidSet.count(Hash) > 0) {
      Hash = Hash * 3 + 1;
    }
    UniqCidSet.insert(Hash);
  }

  LLVM_DEBUG(dbgs() << "[ID] " << Hash << "\n");
  LLVM_DEBUG(dbgs() << "[INS] " << *Inst << "\n");

  return Hash;
}

void AngoraLLVMPass::setValueNonSan(Value *V) {
  if (Instruction *Inst = dyn_cast<Instruction>(V))
    setInsNonSan(Inst);
}

void AngoraLLVMPass::setInsNonSan(Instruction *Inst) {
  if (Inst)
    Inst->setMetadata(NoSanMetaId, NoneMetaNode);
}

void AngoraLLVMPass::initVariables(Module &M) {
  // To ensure different version binaries have the same id
  auto &ModuleIdentifier = M.getModuleIdentifier();
  if (ModuleIdentifier.empty()) {
    report_fatal_error("This Module does not have an identifier");
  }

  ModuleHash = computeModuleHash(ModuleIdentifier);
  LLVM_DEBUG(dbgs() << "Module ID: " << ModuleIdentifier
                    << ", Module Hash: " << ModuleHash << "\n");

  IsBitcode =
      0 == ModuleIdentifier.compare(ModuleIdentifier.length() - 3, 3, ".bc");
  if (IsBitcode) {
    LLVM_DEBUG(dbgs() << "Input is LLVM bitcode\n");
  }

  char *InstRatioString = getenv("ANGORA_INST_RATIO");
  if (InstRatioString) {
    if (sscanf(InstRatioString, "%u", &InstRatio) != 1 || !InstRatio ||
        InstRatio > 100)
      report_fatal_error(
          "Bad value of ANGORA_INST_RATIO (must be between 1 and 100)");
  }
  LLVM_DEBUG(dbgs() << "inst_ratio: " << InstRatio << "\n");

  SerialInstIDCounter = 0;
  InstructionIdDistrib.reset();
  ContextIdDistrib.reset();
  PercentDistrib.reset();

  LLVMContext &C = M.getContext();
  VoidTy = Type::getVoidTy(C);
  Int1Ty = IntegerType::getInt1Ty(C);
  Int8Ty = IntegerType::getInt8Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);
  Int64Ty = IntegerType::getInt64Ty(C);
  Int8PtrTy = PointerType::getUnqual(Int8Ty);
  Int64PtrTy = PointerType::getUnqual(Int64Ty);

  ColdCallWeights = MDBuilder(C).createBranchWeights(1, 1000);

  NoSanMetaId = C.getMDKindID("nosanitize");
  NoneMetaNode = MDNode::get(C, None);

  AngoraContext =
      new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                         ConstantInt::get(Int32Ty, 0), "__angora_context", 0,
                         GlobalVariable::GeneralDynamicTLSModel, 0, false);

  AngoraCallSite =
      new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                         ConstantInt::get(Int32Ty, 0), "__angora_call_site", 0,
                         GlobalVariable::GeneralDynamicTLSModel, 0, false);

  if (FastMode) {
    AngoraMapPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                                      GlobalValue::ExternalLinkage, 0,
                                      "__angora_area_ptr");

    AngoraCondId =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
                           "__angora_cond_cmpid");

    AngoraPrevLoc =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                           ConstantInt::get(Int32Ty, 0), "__angora_prev_loc", 0,
                           GlobalVariable::GeneralDynamicTLSModel, 0, false);

    {
      AttributeList AL;
      AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                           Attribute::NoUnwind);
      Type *TraceCmpArgs[5] = {Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int64Ty};
      TraceCmpTy = FunctionType::get(Int32Ty, TraceCmpArgs, false);
      TraceCmp = M.getOrInsertFunction("__angora_trace_cmp", TraceCmpTy, AL);
    }

    {
      AttributeList AL;
      AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                           Attribute::NoUnwind);
      Type *TraceSwArgs[3] = {Int32Ty, Int32Ty, Int64Ty};
      TraceSwTy = FunctionType::get(Int64Ty, TraceSwArgs, false);
      TraceSw = M.getOrInsertFunction("__angora_trace_switch", TraceSwTy, AL);
    }
  } else if (TrackMode) {
    {
      AttributeList AL;
      AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                           Attribute::NoUnwind);
      Type *TraceCmpTtArgs[7] = {Int32Ty, Int32Ty, Int32Ty, Int32Ty,
                                 Int64Ty, Int64Ty, Int32Ty};
      TraceCmpTtTy = FunctionType::get(VoidTy, TraceCmpTtArgs, false);
      TraceCmpTT =
          M.getOrInsertFunction("__angora_trace_cmp_tt", TraceCmpTtTy, AL);
    }

    {
      AttributeList AL;
      AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                           Attribute::NoUnwind);
      Type *TraceSwTtArgs[6] = {Int32Ty, Int32Ty, Int32Ty,
                                Int64Ty, Int32Ty, Int64PtrTy};
      TraceSwTtTy = FunctionType::get(VoidTy, TraceSwTtArgs, false);
      TraceSwTT =
          M.getOrInsertFunction("__angora_trace_switch_tt", TraceSwTtTy, AL);
    }

    {
      AttributeList AL;
      AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                           Attribute::NoUnwind);
      Type *TraceFnTtArgs[5] = {Int32Ty, Int32Ty, Int32Ty, Int8PtrTy,
                                Int8PtrTy};
      TraceFnTtTy = FunctionType::get(VoidTy, TraceFnTtArgs, false);
      TraceFnTT =
          M.getOrInsertFunction("__angora_trace_fn_tt", TraceFnTtTy, AL);
    }

    {
      AttributeList AL;
      AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,
                           Attribute::NoUnwind);
      Type *TraceExploitTtArgs[5] = {Int32Ty, Int32Ty, Int32Ty, Int32Ty,
                                     Int64Ty};
      TraceExploitTtTy = FunctionType::get(VoidTy, TraceExploitTtArgs, false);
      TraceExploitTT = M.getOrInsertFunction("__angora_trace_exploit_val_tt",
                                             TraceExploitTtTy);
    }
  }

  std::vector<std::string> AllABIListFiles;
  AllABIListFiles.insert(AllABIListFiles.end(), ClABIListFiles.begin(),
                         ClABIListFiles.end());
  ABIList.set(
      SpecialCaseList::createOrDie(AllABIListFiles, *vfs::getRealFileSystem()));

  std::vector<std::string> AllExploitListFiles;
  AllExploitListFiles.insert(AllExploitListFiles.end(),
                             ClExploitListFiles.begin(),
                             ClExploitListFiles.end());
  ExploitList.set(SpecialCaseList::createOrDie(AllExploitListFiles,
                                               *vfs::getRealFileSystem()));

  GenerateIDsRandomly = !!getenv(GEN_ID_RANDOM_VAR);

  NumFnContext = -1;
  char *CustomFnContextString = getenv(CUSTOM_FN_CTX);
  if (CustomFnContextString) {
    NumFnContext = atoi(CustomFnContextString);
    if (NumFnContext < 0 || NumFnContext >= 32) {
      report_fatal_error("custom context should be: >= 0 && < 32");
    }
  }

  if (NumFnContext == 0) {
    LLVM_DEBUG(dbgs() << "disable context\n");
  }

  if (NumFnContext > 0) {
    LLVM_DEBUG(dbgs() << "use custom function call context: " << NumFnContext
                      << "\n");
  }

  if (GenerateIDsRandomly) {
    LLVM_DEBUG(dbgs() << "generate id randomly\n");
  }
};

// Coverage statistics: AFL's Branch count
// Angora enable function-call context.
void AngoraLLVMPass::addEdgeInstrumentation(Module &M, BasicBlock &BB) {
  if (!FastMode || skipBasicBlock())
    return;

  unsigned int BasicBlockID = getRandomBasicBlockId();
  LLVM_DEBUG(dbgs() << "Basic block ID: " << BasicBlockID << "\n");
  ConstantInt *BasicBlockIDVal = ConstantInt::get(Int32Ty, BasicBlockID);

  IRBuilder<> IRB(&BB, BB.getFirstInsertionPt());

  LoadInst *PrevLoc = IRB.CreateLoad(AngoraPrevLoc);
  setInsNonSan(PrevLoc);

  Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, Int32Ty);
  setValueNonSan(PrevLocCasted);

  // Get Map[idx]
  LoadInst *MapPtr = IRB.CreateLoad(AngoraMapPtr);
  setInsNonSan(MapPtr);

  Value *BrId = IRB.CreateXor(PrevLocCasted, BasicBlockIDVal);
  setValueNonSan(BrId);
  Value *MapPtrIdx = IRB.CreateGEP(MapPtr, BrId);
  setValueNonSan(MapPtrIdx);

  // Increase 1 : IncRet <- Map[idx] + 1
  LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
  setInsNonSan(Counter);

  // Implementation of saturating counter.
  // Value *CmpOF = IRB.CreateICmpNE(Counter, ConstantInt::get(Int8Ty, -1));
  // setValueNonSan(CmpOF);
  // Value *IncVal = IRB.CreateZExt(CmpOF, Int8Ty);
  // setValueNonSan(IncVal);
  // Value *IncRet = IRB.CreateAdd(Counter, IncVal);
  // setValueNonSan(IncRet);

  // Implementation of Never-zero counter
  // The idea is from Marc and Heiko in AFLPlusPlus
  // Reference: :
  // https://github.com/vanhauser-thc/AFLplusplus/blob/master/llvm_mode/README.neverzero
  // and https://github.com/vanhauser-thc/AFLplusplus/issues/10

  Value *IncRet = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
  setValueNonSan(IncRet);
  Value *IsZero = IRB.CreateICmpEQ(IncRet, ConstantInt::get(Int8Ty, 0));
  setValueNonSan(IsZero);
  Value *IncVal = IRB.CreateZExt(IsZero, Int8Ty);
  setValueNonSan(IncVal);
  IncRet = IRB.CreateAdd(IncRet, IncVal);
  setValueNonSan(IncRet);

  // Store Back Map[idx]
  IRB.CreateStore(IncRet, MapPtrIdx)->setMetadata(NoSanMetaId, NoneMetaNode);

  Value *NewPrevLoc = nullptr;
  if (NumFnContext != 0) { // Call-based context
    // Load ctx
    LoadInst *CtxVal = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CtxVal);

    Value *CtxValCasted = IRB.CreateZExt(CtxVal, Int32Ty);
    setValueNonSan(CtxValCasted);
    // Update PrevLoc
    NewPrevLoc = IRB.CreateXor(CtxValCasted,
                               ConstantInt::get(Int32Ty, BasicBlockID >> 1));
  } else { // disable context
    NewPrevLoc = ConstantInt::get(Int32Ty, BasicBlockID >> 1);
  }
  setValueNonSan(NewPrevLoc);

  StoreInst *Store = IRB.CreateStore(NewPrevLoc, AngoraPrevLoc);
  setInsNonSan(Store);
};

void AngoraLLVMPass::addFnWrap(Function &F) {

  if (NumFnContext == 0)
    return;

  // *** Pre Fn ***
  BasicBlock &EntryBB = F.getEntryBlock();
  IRBuilder<> PreIRB(&EntryBB, EntryBB.getFirstInsertionPt());

  Value *CallSite = PreIRB.CreateLoad(AngoraCallSite);
  setValueNonSan(CallSite);

  Value *OriginalCtxVal = PreIRB.CreateLoad(AngoraContext);
  setValueNonSan(OriginalCtxVal);

  // ***** Add Context *****
  // instrument code before and after each function call to add context
  // We did `xor` simply.
  // This can avoid recursion. The effect of call in recursion will be removed
  // by `xor` with the same value
  // Implementation of function context for AFL by heiko eissfeldt:
  // https://github.com/vanhauser-thc/afl-patches/blob/master/afl-fuzz-context_sensitive.diff
  if (NumFnContext > 0) {
    OriginalCtxVal = PreIRB.CreateLShr(OriginalCtxVal, 32 / NumFnContext);
    setValueNonSan(OriginalCtxVal);
  }

  Value *UpdatedCtx = PreIRB.CreateXor(OriginalCtxVal, CallSite);
  setValueNonSan(UpdatedCtx);

  StoreInst *SaveCtx = PreIRB.CreateStore(UpdatedCtx, AngoraContext);
  setInsNonSan(SaveCtx);

  // *** Post Fn ***
  for (auto &BB : F) {
    Instruction *Inst = BB.getTerminator();
    if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
      // ***** Reload Context *****
      IRBuilder<> PostIRB(Inst);
      PostIRB.CreateStore(OriginalCtxVal, AngoraContext)
          ->setMetadata(NoSanMetaId, NoneMetaNode);
    }
  }
}

void AngoraLLVMPass::processCall(CallBase *CB) {
  visitCompareFunc(CB);
  visitExploitation(CB);

  //  if (ABIList.isIn(*Callee, "uninstrumented"))
  //  return;
  if (NumFnContext != 0) {
    auto CallSiteID = getRandomContextId();

    IRBuilder<> IRB(CB);
    Constant *CallSiteIDValue = ConstantInt::get(Int32Ty, CallSiteID);
    IRB.CreateStore(CallSiteIDValue, AngoraCallSite)
        ->setMetadata(NoSanMetaId, NoneMetaNode);

    LLVM_DEBUG(dbgs() << "Marking call site: (" << CallSiteID << ", "
                      << CB->getCalledFunction()->getName() << ")\n");
  }
}

void AngoraLLVMPass::visitCallInst(CallInst *CI) {
  Function *Callee = CI->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(CI->getCalledOperand())) {
    return;
  }

  // remove inserted "unfold" functions
  if (!Callee->getName().compare(StringRef("__unfold_branch_fn"))) {
    if (CI->use_empty()) {
      CI->eraseFromParent();
    }
    return;
  }

  processCall(CI);
};

void AngoraLLVMPass::visitInvokeInst(InvokeInst *II) {
  Function *Callee = II->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(II->getCalledOperand())) {
    return;
  }

  processCall(II);
}

void AngoraLLVMPass::visitCompareFunc(CallBase *Inst) {
  // configuration file: custom/exploitation_list.txt  fun:xx=cmpfn

  if (!isa<CallInst>(Inst) || !ExploitList.isIn(*Inst, CompareFuncCat)) {
    return;
  }
  ConstantInt *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));

  if (!TrackMode)
    return;

  CallInst *Caller = cast<CallInst>(Inst);
  Value *OpArg[2];
  OpArg[0] = Caller->getArgOperand(0);
  OpArg[1] = Caller->getArgOperand(1);

  if (!OpArg[0]->getType()->isPointerTy() ||
      !OpArg[1]->getType()->isPointerTy()) {
    return;
  }

  IRBuilder<> IRB(Inst);

  Value *ArgSize = nullptr;
  if (Caller->getNumArgOperands() > 2) {
    ArgSize = Caller->getArgOperand(2); // size_t
    ArgSize = IRB.CreateZExtOrTrunc(ArgSize, Int32Ty);
  } else {
    ArgSize = ConstantInt::get(Int32Ty, 0);
  }

  LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
  setInsNonSan(CurCtx);
  CallInst *ProxyCall =
      IRB.CreateCall(TraceFnTT, {Cid, CurCtx, ArgSize, OpArg[0], OpArg[1]});
  setInsNonSan(ProxyCall);
}

Value *AngoraLLVMPass::castArgType(IRBuilder<> &IRB, Value *V) {
  Type *OpType = V->getType();
  Value *NV = V;
  if (OpType->isFloatTy()) {
    NV = IRB.CreateFPToUI(V, Int32Ty);
    setValueNonSan(NV);
    NV = IRB.CreateIntCast(NV, Int64Ty, false);
    setValueNonSan(NV);
  } else if (OpType->isDoubleTy()) {
    NV = IRB.CreateFPToUI(V, Int64Ty);
    setValueNonSan(NV);
  } else if (OpType->isPointerTy()) {
    NV = IRB.CreatePtrToInt(V, Int64Ty);
  } else {
    if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64) {
      NV = IRB.CreateZExt(V, Int64Ty);
    }
  }
  return NV;
}

void AngoraLLVMPass::processCmp(CmpInst *Cmp, Constant *Cid,
                                Instruction *InsertPoint) {
  Value *OpArg[2];
  OpArg[0] = Cmp->getOperand(0);
  OpArg[1] = Cmp->getOperand(1);
  Type *OpType = OpArg[0]->getType();
  if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
        OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy())) {
    processBoolCmp(Cmp, Cid, InsertPoint);
    return;
  }
  int NumBytes = OpType->getScalarSizeInBits() / 8;
  if (NumBytes == 0) {
    if (OpType->isPointerTy()) {
      NumBytes = 8;
    } else {
      return;
    }
  }

  IRBuilder<> IRB(InsertPoint);

  if (FastMode) {
    /*
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNonSan(ProxyCall);
    */
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId, "angora_target_cond_id");
    setInsNonSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid, "angora_is_target_cond");
    setValueNonSan(CmpEq);

    BranchInst *BI = cast<BranchInst>(
        SplitBlockAndInsertIfThen(CmpEq, InsertPoint, false, ColdCallWeights));
    setInsNonSan(BI);

    IRBuilder<> ThenB(BI);
    OpArg[0] = castArgType(ThenB, OpArg[0]);
    OpArg[1] = castArgType(ThenB, OpArg[1]);
    Value *CondExt = ThenB.CreateZExt(Cmp, Int32Ty, "angora_cond_result");
    setValueNonSan(CondExt);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext, "angora_context");
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        ThenB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNonSan(ProxyCall);
  } else if (TrackMode) {
    Value *SizeArg = ConstantInt::get(Int32Ty, NumBytes);
    uint32_t Predicate = Cmp->getPredicate();
    if (ConstantInt *CInt = dyn_cast<ConstantInt>(OpArg[1])) {
      if (CInt->isNegative()) {
        Predicate |= COND_SIGN_MASK;
      }
    }
    Value *TypeArg = ConstantInt::get(Int32Ty, Predicate);
    Value *CondExt = IRB.CreateZExt(Cmp, Int32Ty);
    setValueNonSan(CondExt);
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmpTT, {Cid, CurCtx, SizeArg, TypeArg, OpArg[0],
                                    OpArg[1], CondExt});
    setInsNonSan(ProxyCall);
  }
}

void AngoraLLVMPass::processBoolCmp(Value *Cond, Constant *Cid,
                                    Instruction *InsertPoint) {
  if (!Cond->getType()->isIntegerTy() ||
      Cond->getType()->getIntegerBitWidth() > 32)
    return;
  Value *OpArg[2];
  OpArg[1] = ConstantInt::get(Int64Ty, 1);
  IRBuilder<> IRB(InsertPoint);
  if (FastMode) {
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId);
    setInsNonSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid);
    setValueNonSan(CmpEq);
    BranchInst *BI = cast<BranchInst>(
        SplitBlockAndInsertIfThen(CmpEq, InsertPoint, false, ColdCallWeights));
    setInsNonSan(BI);
    IRBuilder<> ThenB(BI);
    Value *CondExt = ThenB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    OpArg[0] = ThenB.CreateZExt(CondExt, Int64Ty);
    setValueNonSan(OpArg[0]);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        ThenB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNonSan(ProxyCall);
  } else if (TrackMode) {
    Value *SizeArg = ConstantInt::get(Int32Ty, 1);
    Value *TypeArg = ConstantInt::get(Int32Ty, COND_EQ_OP | COND_BOOL_MASK);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNonSan(CondExt);
    OpArg[0] = IRB.CreateZExt(CondExt, Int64Ty);
    setValueNonSan(OpArg[0]);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmpTT, {Cid, CurCtx, SizeArg, TypeArg, OpArg[0],
                                    OpArg[1], CondExt});
    setInsNonSan(ProxyCall);
  }
}

void AngoraLLVMPass::visitCmpInst(CmpInst *CI) {
  Instruction *InsertPoint = CI->getNextNode();
  if (!InsertPoint || isa<ConstantInt>(CI))
    return;
  Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(CI));
  processCmp(CI, Cid, InsertPoint);
}

void AngoraLLVMPass::visitBranchInst(BranchInst *Br) {
  if (Br->isConditional()) {
    Value *Cond = Br->getCondition();
    if (Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond)) {
      if (!isa<CmpInst>(Cond)) {
        // From  and, or, call, phi ....
        Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Br));
        processBoolCmp(Cond, Cid, Br);
      }
    }
  }
}

void AngoraLLVMPass::visitSwitchInst(Module &M, SwitchInst *SI) {
  Value *Cond = SI->getCondition();
  assert(Cond);
  assert(Cond->getType()->isIntegerTy());
  if (isa<ConstantInt>(Cond)) {
    return;
  }

  int NumBits = Cond->getType()->getScalarSizeInBits();
  int NumBytes = NumBits / 8;
  if (NumBytes == 0 || NumBits % 8 != 0)
    return;

  Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(SI));
  IRBuilder<> IRB(SI);

  if (FastMode) {
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId);
    setInsNonSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid);
    setValueNonSan(CmpEq);
    BranchInst *BI = cast<BranchInst>(
        SplitBlockAndInsertIfThen(CmpEq, SI, false, ColdCallWeights));
    setInsNonSan(BI);
    IRBuilder<> ThenB(BI);
    Value *CondExt = ThenB.CreateZExt(Cond, Int64Ty);
    setValueNonSan(CondExt);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    CallInst *ProxyCall = ThenB.CreateCall(TraceSw, {Cid, CurCtx, CondExt});
    setInsNonSan(ProxyCall);
  } else if (TrackMode) {

    SmallVector<Constant *, 16> CaseValuesList;
    for (auto &Case : SI->cases()) {
      auto *CaseValue = Case.getCaseValue();
      if (CaseValue->getBitWidth() > Int64Ty->getBitWidth())
        continue;
      CaseValuesList.push_back(
          ConstantExpr::getIntegerCast(CaseValue, Int64Ty, false));
    }

    ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, CaseValuesList.size());
    GlobalVariable *ArgGV = new GlobalVariable(
        M, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
        ConstantArray::get(ArrayOfInt64Ty, CaseValuesList),
        "__angora_switch_arg_values");

    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNonSan(CurCtx);
    Value *SizeArg = ConstantInt::get(Int32Ty, NumBytes);
    Value *CondExt = IRB.CreateZExt(Cond, Int64Ty);
    setValueNonSan(CondExt);
    Value *CasesNum = ConstantInt::get(Int32Ty, CaseValuesList.size());
    Value *ArrPtr = IRB.CreatePointerCast(ArgGV, Int64PtrTy);
    setValueNonSan(ArrPtr);
    CallInst *ProxyCall = IRB.CreateCall(
        TraceSwTT, {Cid, CurCtx, SizeArg, CondExt, CasesNum, ArrPtr});
    setInsNonSan(ProxyCall);
  }
}

void AngoraLLVMPass::visitExploitation(Instruction *Inst) {
  // For each instruction and called function.
  bool ExploitAll = ExploitList.isIn(*Inst, ExploitCategoryAll);
  IRBuilder<> IRB(Inst);
  int NumParams = Inst->getNumOperands();
  CallInst *Caller = dyn_cast<CallInst>(Inst);

  if (Caller) {
    NumParams = Caller->getNumArgOperands();
  }

  Value *TypeArg =
      ConstantInt::get(Int32Ty, COND_EXPLOIT_MASK | Inst->getOpcode());

  for (int Idx = 0; Idx < NumParams && Idx < MAX_EXPLOIT_CATEGORY; Idx++) {
    if (ExploitAll || ExploitList.isIn(*Inst, ExploitCategory[Idx])) {
      Value *ParamVal = NULL;
      if (Caller) {
        ParamVal = Caller->getArgOperand(Idx);
      } else {
        ParamVal = Inst->getOperand(Idx);
      }
      Type *ParamType = ParamVal->getType();
      if (ParamType->isIntegerTy() || ParamType->isPointerTy()) {
        if (!isa<ConstantInt>(ParamVal)) {
          ConstantInt *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
          int Size = ParamVal->getType()->getScalarSizeInBits() / 8;
          if (ParamType->isPointerTy()) {
            Size = 8;
            ParamVal = IRB.CreatePtrToInt(ParamVal, Int64Ty);
          } else if (!ParamType->isIntegerTy(64)) {
            ParamVal = IRB.CreateZExt(ParamVal, Int64Ty);
          }
          Value *SizeArg = ConstantInt::get(Int32Ty, Size);

          if (TrackMode) {
            LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
            setInsNonSan(CurCtx);
            CallInst *ProxyCall = IRB.CreateCall(
                TraceExploitTT, {Cid, CurCtx, SizeArg, TypeArg, ParamVal});
            setInsNonSan(ProxyCall);
          }
        }
      }
    }
  }
}

bool AngoraLLVMPass::runOnModule(Module &M) {
  if (TrackMode) {
    LLVM_DEBUG(dbgs() << "Track Mode.\n");
  } else if (DFSanMode) {
    LLVM_DEBUG(dbgs() << "DFSan Mode.\n");
  } else {
    LLVM_DEBUG(dbgs() << "Fast Mode.\n");
    FastMode = true;
  }

  initVariables(M);

  if (DFSanMode)
    return true;

  for (auto &F : M) {
    if (F.isDeclaration() || F.getName().startswith(StringRef("asan.module")))
      continue;

    LLVM_DEBUG(dbgs() << "\nProcessing function: " << F.getName() << "\n");
    auto FunctionHash = hash_combine(ModuleHash, hash_value(F.getName()));
    reseedRandNumGenerators(FunctionHash);

    addFnWrap(F);

    std::vector<BasicBlock *> OriginalBBs;
    for (auto &BB : F)
      OriginalBBs.push_back(&BB);

    for (auto *BB : OriginalBBs) {
      LLVM_DEBUG(dbgs() << "Processing new basic block\n");
      std::vector<Instruction *> OriginalInsts;

      for (auto &Inst : *BB) {
        OriginalInsts.push_back(&Inst);
      }

      addEdgeInstrumentation(M, *BB);

      for (auto *Inst : OriginalInsts) {
        if (Inst->getMetadata(NoSanMetaId))
          continue;

        if (auto *CI = dyn_cast<CallInst>(Inst)) {
          visitCallInst(CI);
        } else if (auto *II = dyn_cast<InvokeInst>(Inst)) {
          visitInvokeInst(II);
        } else if (auto *BI = dyn_cast<BranchInst>(Inst)) {
          visitBranchInst(BI);
        } else if (auto *SI = dyn_cast<SwitchInst>(Inst)) {
          visitSwitchInst(M, SI);
        } else if (auto *CI = dyn_cast<CmpInst>(Inst)) {
          visitCmpInst(CI);
        } else {
          visitExploitation(Inst);
        }
      }
    }
  }

  if (IsBitcode)
    LLVM_DEBUG(dbgs() << "Max constraint id is " << SerialInstIDCounter
                      << "\n");

  return true;
}

static void registerAngoraLLVMPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM) {
  PM.add(new AngoraLLVMPass());
}

static RegisterPass<AngoraLLVMPass> RegisterAngoraLLVMPass("angora_llvm_pass",
                                                           "Angora LLVM Pass",
                                                           false, false);

static RegisterStandardPasses
    RegisterAngoraLLVMPassOptimizerLast(PassManagerBuilder::EP_OptimizerLast,
                                        registerAngoraLLVMPass);

static RegisterStandardPasses
    RegisterAngoraLLVMPassOnOptLevel0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                                      registerAngoraLLVMPass);
