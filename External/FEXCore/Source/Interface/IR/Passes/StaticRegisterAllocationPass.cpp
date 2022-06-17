/*
$info$
tags: ir|opts
desc: Replaces Load/StoreContext with Load/StoreReg for SRA regs
$end_info$
*/

#include "Interface/IR/PassManager.h"
#include <FEXCore/Core/CoreState.h>
#include <FEXCore/IR/IR.h>
#include <FEXCore/IR/IREmitter.h>
#include <FEXCore/IR/IntrusiveIRList.h>
#include <FEXCore/Utils/LogManager.h>

#include <memory>
#include <stddef.h>
#include <stdint.h>

namespace FEXCore::IR {

class StaticRegisterAllocationPass final : public FEXCore::IR::Pass {
public:
  bool Run(IREmitter *IREmit) override;
};

bool IsStaticAllocGpr(uint32_t Offset, RegisterClassType Class) {
  const auto begin = offsetof(FEXCore::Core::CPUState, gregs[0]);
  const auto end = offsetof(FEXCore::Core::CPUState, gregs[16]);

  if (Offset >= begin && Offset < end) {
    const auto reg = (Offset - begin) / 8;
    LOGMAN_THROW_A_FMT(Class == IR::GPRClass, "unexpected Class {}", Class);

    // 0..15 -> 16 in total
    return reg < 16;
  }

  return false;
}

bool IsStaticAllocFpr(uint32_t Offset, RegisterClassType Class, bool AllowGpr) {
  const auto begin = offsetof(FEXCore::Core::CPUState, xmm[0][0]);
  const auto end = offsetof(FEXCore::Core::CPUState, xmm[16][0]);

  if (Offset >= begin && Offset < end) {
    const auto reg = (Offset - begin) / FEXCore::Core::CPUState::XMM_SIZE;
    LogMan::Msg::IFmt("STATIC_ALLOC OFFSET: {}", Offset);
    LogMan::Msg::IFmt("STATIC_ALLOC BEGIN: {}", begin);
    LogMan::Msg::IFmt("IS STATIC ALLOC FPR REG {}", reg);
    LOGMAN_THROW_A_FMT(Class == IR::FPRClass || (AllowGpr && Class == IR::GPRClass), "unexpected Class {}, AllowGpr {}", Class, AllowGpr);

    // 0..15 -> 16 in total
    return reg < 16;
  }

  return false;
}
/**
 * @brief This pass replaces Load/Store Context with Load/Store Register for Statically Mapped registers. It also does some validation.
 *
 */
bool StaticRegisterAllocationPass::Run(IREmitter *IREmit) {
  auto CurrentIR = IREmit->ViewIR();

  for (auto [BlockNode, BlockIROp] : CurrentIR.GetBlocks()) {
      for (auto [CodeNode, IROp] : CurrentIR.GetCode(BlockNode)) {
        IREmit->SetWriteCursor(CodeNode);

        if (IROp->Op == OP_LOADCONTEXT) {
            auto Op = IROp->CW<IR::IROp_LoadContext>();

            if (IsStaticAllocGpr(Op->Offset, Op->Class) || IsStaticAllocFpr(Op->Offset, Op->Class, true)) {
              auto GeneralClass = Op->Class;
              if (IsStaticAllocFpr(Op->Offset, GeneralClass, true) && GeneralClass == GPRClass) {
                GeneralClass = FPRClass;
              }
              auto StaticClass = GeneralClass == GPRClass ? GPRFixedClass : FPRFixedClass;
              OrderedNode *sraReg = IREmit->_LoadRegister(false, Op->Offset, GeneralClass, StaticClass, Op->Header.Size);
              if (GeneralClass != Op->Class) {
                sraReg = IREmit->_VExtractToGPR(Op->Header.Size, Op->Header.Size, sraReg, 0);
              }
              IREmit->ReplaceAllUsesWith(CodeNode, sraReg);
            }
        } if (IROp->Op == OP_STORECONTEXT) {
            auto Op = IROp->CW<IR::IROp_StoreContext>();

            if (IsStaticAllocGpr(Op->Offset, Op->Class) || IsStaticAllocFpr(Op->Offset, Op->Class, true)) {
              auto val = IREmit->UnwrapNode(Op->Value);

              auto GeneralClass = Op->Class;
              if (IsStaticAllocFpr(Op->Offset, GeneralClass, true) && GeneralClass == GPRClass) {
                val = IREmit->_VCastFromGPR(Op->Header.Size, Op->Header.Size, val);
                GeneralClass = FPRClass;
              }

              auto StaticClass = GeneralClass == GPRClass ? GPRFixedClass : FPRFixedClass;
              IREmit->_StoreRegister(val, false, Op->Offset, GeneralClass, StaticClass, Op->Header.Size);

              IREmit->Remove(CodeNode);
            }
        }
    }
  }

  return true;
}

std::unique_ptr<FEXCore::IR::Pass> CreateStaticRegisterAllocationPass() {
  return std::make_unique<StaticRegisterAllocationPass>();
}

}
