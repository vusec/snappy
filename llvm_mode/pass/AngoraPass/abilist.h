#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/SpecialCaseList.h"

using namespace llvm;

static StringRef getGlobalTypeString(const GlobalValue &G) {
  // Types of GlobalVariables are always pointer types.
  Type *GType = G.getValueType();
  // For now we support blacklisting struct types only.
  if (StructType *SGType = dyn_cast<StructType>(GType)) {
    if (!SGType->isLiteral())
      return SGType->getName();
  }
  return "<unknown type>";
}

class AngoraABIList {
  std::unique_ptr<SpecialCaseList> SCL;

public:
  AngoraABIList() = default;

  void set(std::unique_ptr<SpecialCaseList> List) { SCL = std::move(List); }

  /// Returns whether either this function or its source file are listed in the
  /// given category.
  bool isIn(const Function &F, StringRef Category) const {
    return isIn(*F.getParent(), Category) ||
           SCL->inSection("angora", "fun", F.getName(), Category);
  }

  bool isIn(Instruction &Inst, StringRef Category) const {
    if (isa<CallInst>(&Inst)) {
      CallInst *Caller = dyn_cast<CallInst>(&Inst);
      return SCL->inSection("angora", "fun",
                            Caller->getCalledFunction()->getName(), Category);
    }
    return SCL->inSection("angora", "ins", Inst.getOpcodeName(), Category);
  }

  /// Returns whether this global alias is listed in the given category.
  ///
  /// If GA aliases a function, the alias's name is matched as a function name
  /// would be.  Similarly, aliases of globals are matched like globals.
  bool isIn(const GlobalAlias &GA, StringRef Category) const {
    if (isIn(*GA.getParent(), Category))
      return true;

    if (isa<FunctionType>(GA.getValueType()))
      return SCL->inSection("angora", "fun", GA.getName(), Category);

    return SCL->inSection("angora", "global", GA.getName(), Category) ||
           SCL->inSection("angora", "type", getGlobalTypeString(GA), Category);
  }

  /// Returns whether this module is listed in the given category.
  bool isIn(const Module &M, StringRef Category) const {
    return SCL->inSection("angora", "src", M.getModuleIdentifier(), Category);
  }
};
