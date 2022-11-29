/*
$info$
tags: backend|arm64
$end_info$
*/

#include "Interface/Core/JIT/Arm64/JITClass.h"
#include "Interface/IR/Passes/RegisterAllocationPass.h"

namespace FEXCore::CPU {
using namespace vixl;
using namespace vixl::aarch64;
#define DEF_OP(x) void Arm64JITCore::Op_##x(IR::IROp_Header *IROp, IR::NodeID Node)

DEF_OP(AESImc) {
  auto Op = IROp->C<IR::IROp_VAESImc>();
  aesimc(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B());
}

DEF_OP(AESEnc) {
	auto Op = IROp->C<IR::IROp_VAESEnc>();
  eor(VTMP2.V16B(), VTMP2.V16B(), VTMP2.V16B());
  mov(VTMP1.V16B(), GetSrc(Op->State.ID()).V16B());
  aese(VTMP1.V16B(), VTMP2.V16B());
  aesmc(VTMP1.V16B(), VTMP1.V16B());
  eor(GetDst(Node).V16B(), VTMP1.V16B(), GetSrc(Op->Key.ID()).V16B());
}

DEF_OP(AESEncLast) {
	auto Op = IROp->C<IR::IROp_VAESEncLast>();
  eor(VTMP2.V16B(), VTMP2.V16B(), VTMP2.V16B());
  mov(VTMP1.V16B(), GetSrc(Op->State.ID()).V16B());
  aese(VTMP1.V16B(), VTMP2.V16B());
  eor(GetDst(Node).V16B(), VTMP1.V16B(), GetSrc(Op->Key.ID()).V16B());
}

DEF_OP(AESDec) {
	auto Op = IROp->C<IR::IROp_VAESDec>();
  eor(VTMP2.V16B(), VTMP2.V16B(), VTMP2.V16B());
  mov(VTMP1.V16B(), GetSrc(Op->State.ID()).V16B());
  aesd(VTMP1.V16B(), VTMP2.V16B());
  aesimc(VTMP1.V16B(), VTMP1.V16B());
  eor(GetDst(Node).V16B(), VTMP1.V16B(), GetSrc(Op->Key.ID()).V16B());
}

DEF_OP(AESDecLast) {
	auto Op = IROp->C<IR::IROp_VAESDecLast>();
  eor(VTMP2.V16B(), VTMP2.V16B(), VTMP2.V16B());
  mov(VTMP1.V16B(), GetSrc(Op->State.ID()).V16B());
  aesd(VTMP1.V16B(), VTMP2.V16B());
  eor(GetDst(Node).V16B(), VTMP1.V16B(), GetSrc(Op->Key.ID()).V16B());
}

DEF_OP(AESKeyGenAssist) {
	auto Op = IROp->C<IR::IROp_VAESKeyGenAssist>();

  aarch64::Literal ConstantLiteral (0x0C030609'0306090CULL, 0x040B0E01'0B0E0104ULL);
  aarch64::Label PastConstant;

  // Do a "regular" AESE step
  eor(VTMP2.V16B(), VTMP2.V16B(), VTMP2.V16B());
  mov(VTMP1.V16B(), GetSrc(Op->Src.ID()).V16B());
  aese(VTMP1.V16B(), VTMP2.V16B());

  // Do a table shuffle to undo ShiftRows
  ldr(VTMP3, &ConstantLiteral);

  // Now EOR in the RCON
  if (Op->RCON) {
    tbl(VTMP1.V16B(), VTMP1.V16B(), VTMP3.V16B());

    LoadConstant(TMP1.W(), Op->RCON);
    ins(VTMP2.V4S(), 1, TMP1.W());
    ins(VTMP2.V4S(), 3, TMP1.W());
    eor(GetDst(Node).V16B(), VTMP1.V16B(), VTMP2.V16B());
  }
  else {
    tbl(GetDst(Node).V16B(), VTMP1.V16B(), VTMP3.V16B());
  }

  b(&PastConstant);
  place(&ConstantLiteral);
  bind(&PastConstant);
}

DEF_OP(CRC32) {
  auto Op = IROp->C<IR::IROp_CRC32>();
  switch (Op->SrcSize) {
    case 1:
      crc32cb(GetReg<RA_32>(Node), GetReg<RA_32>(Op->Src1.ID()), GetReg<RA_32>(Op->Src2.ID()));
      break;
    case 2:
      crc32ch(GetReg<RA_32>(Node), GetReg<RA_32>(Op->Src1.ID()), GetReg<RA_32>(Op->Src2.ID()));
      break;
    case 4:
      crc32cw(GetReg<RA_32>(Node), GetReg<RA_32>(Op->Src1.ID()), GetReg<RA_32>(Op->Src2.ID()));
      break;
    case 8:
      crc32cx(GetReg<RA_32>(Node), GetReg<RA_32>(Op->Src1.ID()), GetReg<RA_64>(Op->Src2.ID()));
      break;
    default: LOGMAN_MSG_A_FMT("Unknown CRC32 size: {}", Op->SrcSize);
  }
}

DEF_OP(PCLMUL) {
  const auto Op = IROp->C<IR::IROp_PCLMUL>();
  const auto OpSize = IROp->Size;
  const auto Is256Bit = OpSize == Core::CPUState::XMM_AVX_REG_SIZE;

  const auto Dst  = GetDst(Node);
  const auto Src1 = GetSrc(Op->Src1.ID());
  const auto Src2 = GetSrc(Op->Src2.ID());

  switch (Op->Selector) {
  case 0b00000000:
    if (Is256Bit) {
      pmullb(Dst.Z().VnQ(), Src1.Z().VnD(), Src2.Z().VnD());
    } else {
      pmull(Dst.Q(), Src1.V2D(), Src2.V2D());
    }
    break;
  case 0b00000001:
    if (Is256Bit) {
      dup(VTMP1.Z().VnD(), Src1.Z().VnD(), 1);
      dup(VTMP2.Z().VnD(), Src1.Z().VnD(), 3);

      pmullb(VTMP1.Z().VnQ(), VTMP1.Z().VnD(), Src2.Z().VnD());
      pmullb(Dst.Z().VnQ(), VTMP2.Z().VnD(), Src2.Z().VnD());

      ptrue(p0.VnD(), SVE_VL1);

      mov(Dst.Z().VnD(), p0.Merging(), VTMP1.Z().VnD());
    } else {
      mov(VTMP1.V1D(), Src1.V2D(), 1);
      pmull(Dst.Q(), VTMP1.V2D(), Src2.V2D());
    }
    break;
  case 0b00010000:
    if (Is256Bit) {
      dup(VTMP1.Z().VnD(), Src2.Z().VnD(), 1);
      dup(VTMP2.Z().VnD(), Src2.Z().VnD(), 3);

      pmullb(VTMP1.Z().VnQ(), VTMP1.Z().VnD(), Src1.Z().VnD());
      pmullb(Dst.Z().VnQ(), VTMP2.Z().VnD(), Src1.Z().VnD());

      ptrue(p0.VnD(), SVE_VL1);

      mov(Dst.Z().VnD(), p0.Merging(), VTMP1.Z().VnD());
    } else {
      mov(VTMP1.V1D(), Src2.V2D(), 1);
      pmull(Dst.Q(), VTMP1.V2D(), Src1.V2D());
    }
    break;
  case 0b00010001:
    if (Is256Bit) {
      pmullt(Dst.Z().VnQ(), Src1.Z().VnD(), Src2.Z().VnD());
    } else {
      pmull2(Dst.Q(), Src1.V2D(), Src2.V2D());
    }
    break;
  default:
    LOGMAN_MSG_A_FMT("Unknown PCLMUL selector: {}", Op->Selector);
    break;
  }
}

#undef DEF_OP
void Arm64JITCore::RegisterEncryptionHandlers() {
#define REGISTER_OP(op, x) OpHandlers[FEXCore::IR::IROps::OP_##op] = &Arm64JITCore::Op_##x
  REGISTER_OP(VAESIMC,           AESImc);
  REGISTER_OP(VAESENC,           AESEnc);
  REGISTER_OP(VAESENCLAST,       AESEncLast);
  REGISTER_OP(VAESDEC,           AESDec);
  REGISTER_OP(VAESDECLAST,       AESDecLast);
  REGISTER_OP(VAESKEYGENASSIST,  AESKeyGenAssist);
  REGISTER_OP(CRC32,             CRC32);
  REGISTER_OP(PCLMUL,            PCLMUL);
#undef REGISTER_OP
}
}
