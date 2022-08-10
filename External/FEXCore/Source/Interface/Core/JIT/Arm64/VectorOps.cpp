/*
$info$
tags: backend|arm64
$end_info$
*/

#include "Interface/Core/JIT/Arm64/JITClass.h"

namespace FEXCore::CPU {

using namespace vixl;
using namespace vixl::aarch64;
#define DEF_OP(x) void Arm64JITCore::Op_##x(IR::IROp_Header *IROp, IR::NodeID Node)
DEF_OP(VectorZero) {
  const uint8_t OpSize = IROp->Size;

  if (CanUseSVE) {
    const auto Dst = GetDst(Node).Z().VnD();
    eor(Dst, Dst, Dst);
  } else {
    switch (OpSize) {
      case 8: {
        const auto Dst = GetDst(Node).V8B();
        eor(Dst, Dst, Dst);
        break;
      }
      case 16: {
        const auto Dst = GetDst(Node).V16B();
        eor(Dst, Dst, Dst);
        break;
      }
      default:
        LOGMAN_MSG_A_FMT("Unknown Element Size: {}", OpSize);
        break;
    }
  }
}

DEF_OP(VectorImm) {
  auto Op = IROp->C<IR::IROp_VectorImm>();

  const uint8_t OpSize = IROp->Size;
  const uint8_t ElementSize = Op->Header.ElementSize;
  const uint8_t Elements = OpSize / ElementSize;

  if (CanUseSVE) {
    const auto Dst = [&] {
      const auto Tmp = GetDst(Node).Z();
      switch (ElementSize) {
      case 1:
        return Tmp.VnB();
      case 2:
        return Tmp.VnH();
      case 4:
        return Tmp.VnS();
      case 8:
        return Tmp.VnD();
      default:
        LOGMAN_MSG_A_FMT("Unhandled element size: {}", ElementSize);
        return Tmp;
      }
    }();

    dup(Dst, Op->Immediate);
  } else {
    if (ElementSize == 8) {
      // movi with 64bit element size doesn't do what we want here
      LoadConstant(TMP1.X(), Op->Immediate);
      dup(GetDst(Node).V2D(), TMP1.X());
    }
    else {
      movi(GetDst(Node).VCast(OpSize * 8, Elements), Op->Immediate);
    }
  }
}

DEF_OP(SplatVector2) {
  auto Op = IROp->C<IR::IROp_SplatVector2>();
  const uint8_t OpSize = IROp->Size;
  LOGMAN_THROW_AA_FMT(OpSize <= 16, "Can't handle a vector of size: {}", OpSize);

  const uint8_t ElementSize = OpSize / 2;

  switch (ElementSize) {
    case 4:
      dup(GetDst(Node).V4S(), GetSrc(Op->Scalar.ID()).V4S(), 0);
    break;
    case 8:
      dup(GetDst(Node).V2D(), GetSrc(Op->Scalar.ID()).V2D(), 0);
    break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.Size); break;
  }
}

DEF_OP(SplatVector4) {
  auto Op = IROp->C<IR::IROp_SplatVector4>();
  const uint8_t OpSize = IROp->Size;
  LOGMAN_THROW_AA_FMT(OpSize <= 16, "Can't handle a vector of size: {}", OpSize);

  const uint8_t ElementSize = OpSize / 4;

  switch (ElementSize) {
    case 4:
      dup(GetDst(Node).V4S(), GetSrc(Op->Scalar.ID()).V4S(), 0);
    break;
    case 8:
      dup(GetDst(Node).V2D(), GetSrc(Op->Scalar.ID()).V2D(), 0);
    break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.Size); break;
  }
}

DEF_OP(VMov) {
  auto Op = IROp->C<IR::IROp_VMov>();
  const uint8_t OpSize = IROp->Size;

  const auto Dst = GetDst(Node);
  const auto Source = GetSrc(Op->Source.ID());

  switch (OpSize) {
    case 1: {
      eor(VTMP1.V16B(), VTMP1.V16B(), VTMP1.V16B());
      mov(VTMP1.V16B(), 0, Source.V16B(), 0);
      if (CanUseSVE) {
        eor(Dst.Z().VnD(), Dst.Z().VnD(), Dst.Z().VnD());
      }
      mov(Dst, VTMP1);
      break;
    }
    case 2: {
      eor(VTMP1.V16B(), VTMP1.V16B(), VTMP1.V16B());
      mov(VTMP1.V8H(), 0, Source.V8H(), 0);
      if (CanUseSVE) {
        eor(Dst.Z().VnD(), Dst.Z().VnD(), Dst.Z().VnD());
      }
      mov(Dst, VTMP1);
      break;
    }
    case 4: {
      eor(VTMP1.V16B(), VTMP1.V16B(), VTMP1.V16B());
      mov(VTMP1.V4S(), 0, Source.V4S(), 0);
      if (CanUseSVE) {
        eor(Dst.Z().VnD(), Dst.Z().VnD(), Dst.Z().VnD());
      }
      mov(Dst, VTMP1);
      break;
    }
    case 8: {
      if (CanUseSVE) {
        mov(VTMP1.V8B(), Source.V8B());
        eor(Dst.Z().VnD(), Dst.Z().VnD(), Dst.Z().VnD());
        mov(Dst.V8B(), VTMP1.V8B());
      } else {
        mov(Dst.V8B(), Source.V8B());
      }
      break;
    }
    case 16: {
      if (CanUseSVE) {
        mov(VTMP1.V16B(), Source.V16B());
        eor(Dst.Z().VnD(), Dst.Z().VnD(), Dst.Z().VnD());
        mov(Dst.V16B(), VTMP1.V16B());
      } else {
        if (Dst.GetCode() != Source.GetCode()) {
          mov(Dst.V16B(), Source.V16B());
        }
      }
      break;
    }
    case 32: {
      mov(Dst.Z().VnD(), Source.Z().VnD());
      break;
    }
    default:
      LOGMAN_MSG_A_FMT("Unknown Element Size: {}", OpSize);
      break;
  }
}

DEF_OP(VAnd) {
  auto Op = IROp->C<IR::IROp_VAnd>();

  const auto Dst = GetDst(Node);
  const auto Vector1 = GetSrc(Op->Vector1.ID());
  const auto Vector2 = GetSrc(Op->Vector2.ID());

  if (CanUseSVE) {
    and_(Dst.Z().VnD(), Vector1.Z().VnD(), Vector2.Z().VnD());
  } else {
    and_(Dst.V16B(), Vector1.V16B(), Vector2.V16B());
  }
}

DEF_OP(VBic) {
  auto Op = IROp->C<IR::IROp_VBic>();

  const auto Dst = GetDst(Node);
  const auto Vector1 = GetSrc(Op->Vector1.ID());
  const auto Vector2 = GetSrc(Op->Vector2.ID());

  if (CanUseSVE) {
    bic(Dst.Z().VnD(), Vector1.Z().VnD(), Vector2.Z().VnD());
  } else {
    bic(Dst.V16B(), Vector1.V16B(), Vector2.V16B());
  }
}

DEF_OP(VOr) {
  auto Op = IROp->C<IR::IROp_VOr>();

  const auto Dst = GetDst(Node);
  const auto Vector1 = GetSrc(Op->Vector1.ID());
  const auto Vector2 = GetSrc(Op->Vector2.ID());

  if (CanUseSVE) {
    orr(Dst.Z().VnD(), Vector1.Z().VnD(), Vector2.Z().VnD());
  } else {
    orr(Dst.V16B(), Vector1.V16B(), Vector2.V16B());
  }
}

DEF_OP(VXor) {
  auto Op = IROp->C<IR::IROp_VXor>();

  const auto Dst = GetDst(Node);
  const auto Vector1 = GetSrc(Op->Vector1.ID());
  const auto Vector2 = GetSrc(Op->Vector2.ID());

  if (CanUseSVE) {
    eor(Dst.Z().VnD(), Vector1.Z().VnD(), Vector2.Z().VnD());
  } else {
    eor(Dst.V16B(), Vector1.V16B(), Vector2.V16B());
  }
}

DEF_OP(VAdd) {
  auto Op = IROp->C<IR::IROp_VAdd>();
  switch (Op->Header.ElementSize) {
    case 1: {
      add(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      add(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      add(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      add(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VSub) {
  auto Op = IROp->C<IR::IROp_VSub>();
  switch (Op->Header.ElementSize) {
    case 1: {
      sub(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      sub(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      sub(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      sub(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VUQAdd) {
  auto Op = IROp->C<IR::IROp_VUQAdd>();
  switch (Op->Header.ElementSize) {
    case 1: {
      uqadd(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      uqadd(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      uqadd(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      uqadd(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VUQSub) {
  auto Op = IROp->C<IR::IROp_VUQSub>();
  switch (Op->Header.ElementSize) {
    case 1: {
      uqsub(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      uqsub(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      uqsub(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      uqsub(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VSQAdd) {
  auto Op = IROp->C<IR::IROp_VSQAdd>();
  switch (Op->Header.ElementSize) {
    case 1: {
      sqadd(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      sqadd(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      sqadd(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      sqadd(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VSQSub) {
  auto Op = IROp->C<IR::IROp_VSQSub>();
  switch (Op->Header.ElementSize) {
    case 1: {
      sqsub(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      sqsub(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      sqsub(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      sqsub(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VAddP) {
  auto Op = IROp->C<IR::IROp_VAddP>();
  const uint8_t OpSize = IROp->Size;

  if (OpSize == 8) {
    switch (Op->Header.ElementSize) {
      case 1: {
        addp(GetDst(Node).V8B(), GetSrc(Op->VectorLower.ID()).V8B(), GetSrc(Op->VectorUpper.ID()).V8B());
        break;
      }
      case 2: {
        addp(GetDst(Node).V4H(), GetSrc(Op->VectorLower.ID()).V4H(), GetSrc(Op->VectorUpper.ID()).V4H());
        break;
      }
      case 4: {
        addp(GetDst(Node).V2S(), GetSrc(Op->VectorLower.ID()).V2S(), GetSrc(Op->VectorUpper.ID()).V2S());
        break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    switch (Op->Header.ElementSize) {
      case 1: {
        addp(GetDst(Node).V16B(), GetSrc(Op->VectorLower.ID()).V16B(), GetSrc(Op->VectorUpper.ID()).V16B());
        break;
      }
      case 2: {
        addp(GetDst(Node).V8H(), GetSrc(Op->VectorLower.ID()).V8H(), GetSrc(Op->VectorUpper.ID()).V8H());
        break;
      }
      case 4: {
        addp(GetDst(Node).V4S(), GetSrc(Op->VectorLower.ID()).V4S(), GetSrc(Op->VectorUpper.ID()).V4S());
        break;
      }
      case 8: {
        addp(GetDst(Node).V2D(), GetSrc(Op->VectorLower.ID()).V2D(), GetSrc(Op->VectorUpper.ID()).V2D());
        break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VAddV) {
  auto Op = IROp->C<IR::IROp_VAddV>();
  const uint8_t OpSize = IROp->Size;
  const uint8_t Elements = OpSize / Op->Header.ElementSize;
  // Vector
  switch (Op->Header.ElementSize) {
    case 1:
    case 2:
    case 4:
      addv(GetDst(Node).VCast(Op->Header.ElementSize * 8, 1), GetSrc(Op->Vector.ID()).VCast(OpSize * 8, Elements));
      break;
    case 8:
      addp(GetDst(Node).VCast(OpSize * 8, 1), GetSrc(Op->Vector.ID()).VCast(OpSize * 8, Elements));
      break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VUMinV) {
  auto Op = IROp->C<IR::IROp_VUMinV>();
  const uint8_t OpSize = IROp->Size;
  const uint8_t Elements = OpSize / Op->Header.ElementSize;
  // Vector
  switch (Op->Header.ElementSize) {
    case 1:
    case 2:
    case 4:
      uminv(GetDst(Node).VCast(Op->Header.ElementSize * 8, 1), GetSrc(Op->Vector.ID()).VCast(OpSize * 8, Elements));
      break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VURAvg) {
  auto Op = IROp->C<IR::IROp_VURAvg>();
  switch (Op->Header.ElementSize) {
    case 1: {
      urhadd(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      urhadd(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VAbs) {
  auto Op = IROp->C<IR::IROp_VAbs>();
  const uint8_t OpSize = IROp->Size;
  const uint8_t Elements = OpSize / Op->Header.ElementSize;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 8: {
        abs(GetDst(Node).D(), GetSrc(Op->Vector.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 1:
      case 2:
      case 4:
      case 8:
        abs(GetDst(Node).VCast(OpSize * 8, Elements), GetSrc(Op->Vector.ID()).VCast(OpSize * 8, Elements));
        break;
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VPopcount) {
  auto Op = IROp->C<IR::IROp_VPopcount>();
  const uint8_t OpSize = IROp->Size;
  if (OpSize == 8) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 1: {
        cnt(GetDst(Node).V8B(), GetSrc(Op->Vector.ID()).V8B());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 1:
        cnt(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B());
        break;
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFAdd) {
  auto Op = IROp->C<IR::IROp_VFAdd>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fadd(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        fadd(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fadd(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        fadd(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFAddP) {
  auto Op = IROp->C<IR::IROp_VFAddP>();
  switch (Op->Header.ElementSize) {
    case 4: {
      faddp(GetDst(Node).V4S(), GetSrc(Op->VectorLower.ID()).V4S(), GetSrc(Op->VectorUpper.ID()).V4S());
    break;
    }
    case 8: {
      faddp(GetDst(Node).V2D(), GetSrc(Op->VectorLower.ID()).V2D(), GetSrc(Op->VectorUpper.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VFSub) {
  auto Op = IROp->C<IR::IROp_VFSub>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fsub(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        fsub(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fsub(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        fsub(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFMul) {
  auto Op = IROp->C<IR::IROp_VFMul>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fmul(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        fmul(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fmul(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        fmul(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFDiv) {
  auto Op = IROp->C<IR::IROp_VFDiv>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fdiv(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        fdiv(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fdiv(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        fdiv(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFMin) {
  auto Op = IROp->C<IR::IROp_VFMin>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmp(GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
        fcsel(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S(), Condition::mi);
      break;
      }
      case 8: {
        fcmp(GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
        fcsel(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D(), Condition::mi);
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmgt(VTMP1.V4S(), GetSrc(Op->Vector2.ID()).V4S(), GetSrc(Op->Vector1.ID()).V4S());
        mov(VTMP2.V4S(), GetSrc(Op->Vector1.ID()).V4S());
        bif(VTMP2.V16B(), GetSrc(Op->Vector2.ID()).V16B(), VTMP1.V16B());
        mov(GetDst(Node).V4S(), VTMP2.V4S());
      break;
      }
      case 8: {
        fcmgt(VTMP1.V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
        mov(VTMP2.V2D(), GetSrc(Op->Vector1.ID()).V2D());
        bif(VTMP2.V16B(), GetSrc(Op->Vector2.ID()).V16B(), VTMP1.V16B());
        mov(GetDst(Node).V2D(), VTMP2.V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFMax) {
  auto Op = IROp->C<IR::IROp_VFMax>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmp(GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
        fcsel(GetDst(Node).S(), GetSrc(Op->Vector2.ID()).S(), GetSrc(Op->Vector1.ID()).S(), Condition::mi);
      break;
      }
      case 8: {
        fcmp(GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
        fcsel(GetDst(Node).D(), GetSrc(Op->Vector2.ID()).D(), GetSrc(Op->Vector1.ID()).D(), Condition::mi);
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmgt(VTMP1.V4S(), GetSrc(Op->Vector2.ID()).V4S(), GetSrc(Op->Vector1.ID()).V4S());
        mov(VTMP2.V4S(), GetSrc(Op->Vector1.ID()).V4S());
        bit(VTMP2.V16B(), GetSrc(Op->Vector2.ID()).V16B(), VTMP1.V16B());
        mov(GetDst(Node).V4S(), VTMP2.V4S());
      break;
      }
      case 8: {
        fcmgt(VTMP1.V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
        mov(VTMP2.V2D(), GetSrc(Op->Vector1.ID()).V2D());
        bit(VTMP2.V16B(), GetSrc(Op->Vector2.ID()).V16B(), VTMP1.V16B());
        mov(GetDst(Node).V2D(), VTMP2.V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFRecp) {
  auto Op = IROp->C<IR::IROp_VFRecp>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fmov(VTMP1.S(), 1.0f);
        fdiv(GetDst(Node).S(), VTMP1.S(), GetSrc(Op->Vector.ID()).S());
      break;
      }
      case 8: {
        fmov(VTMP1.D(), 1.0);
        fdiv(GetDst(Node).D(), VTMP1.D(), GetSrc(Op->Vector.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fmov(VTMP1.V4S(), 1.0f);
        fdiv(GetDst(Node).V4S(), VTMP1.V4S(), GetSrc(Op->Vector.ID()).V4S());
      break;
      }
      case 8: {
        fmov(VTMP1.V2D(), 1.0);
        fdiv(GetDst(Node).V2D(), VTMP1.V2D(), GetSrc(Op->Vector.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFSqrt) {
  auto Op = IROp->C<IR::IROp_VFRSqrt>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fsqrt(GetDst(Node).S(), GetSrc(Op->Vector.ID()).S());
      break;
      }
      case 8: {
        fsqrt(GetDst(Node).D(), GetSrc(Op->Vector.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fsqrt(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S());
      break;
      }
      case 8: {
        fsqrt(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFRSqrt) {
  auto Op = IROp->C<IR::IROp_VFRSqrt>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fmov(VTMP1.S(), 1.0f);
        fsqrt(VTMP2.S(), GetSrc(Op->Vector.ID()).S());
        fdiv(GetDst(Node).S(), VTMP1.S(), VTMP2.S());
      break;
      }
      case 8: {
        fmov(VTMP1.D(), 1.0);
        fsqrt(VTMP2.D(), GetSrc(Op->Vector.ID()).D());
        fdiv(GetDst(Node).D(), VTMP1.D(), VTMP2.D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 4: {
        fmov(VTMP1.V4S(), 1.0f);
        fsqrt(VTMP2.V4S(), GetSrc(Op->Vector.ID()).V4S());
        fdiv(GetDst(Node).V4S(), VTMP1.V4S(), VTMP2.V4S());
      break;
      }
      case 8: {
        fmov(VTMP1.V2D(), 1.0);
        fsqrt(VTMP2.V2D(), GetSrc(Op->Vector.ID()).V2D());
        fdiv(GetDst(Node).V2D(), VTMP1.V2D(), VTMP2.V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VNeg) {
  auto Op = IROp->C<IR::IROp_VNeg>();
  switch (Op->Header.ElementSize) {
  case 1:
    neg(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B());
    break;
  case 2:
    neg(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H());
    break;
  case 4:
    neg(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S());
    break;
  case 8:
    neg(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D());
    break;
  default: LOGMAN_MSG_A_FMT("Unsupported VNeg size: {}", IROp->Size);
  }
}

DEF_OP(VFNeg) {
  auto Op = IROp->C<IR::IROp_VFNeg>();
  switch (Op->Header.ElementSize) {
  case 4:
    fneg(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S());
    break;
  case 8:
    fneg(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D());
    break;
  default: LOGMAN_MSG_A_FMT("Unsupported VFNeg size: {}", IROp->Size);
  }
}

DEF_OP(VNot) {
  auto Op = IROp->C<IR::IROp_VNot>();
  mvn(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B());
}

DEF_OP(VUMin) {
  auto Op = IROp->C<IR::IROp_VUMin>();
  switch (Op->Header.ElementSize) {
    case 1: {
      umin(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      umin(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      umin(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      cmhi(VTMP1.V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
      mov(VTMP2.V2D(), GetSrc(Op->Vector1.ID()).V2D());
      bif(VTMP2.V16B(), GetSrc(Op->Vector2.ID()).V16B(), VTMP1.V16B());
      mov(GetDst(Node).V2D(), VTMP2.V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VSMin) {
  auto Op = IROp->C<IR::IROp_VSMin>();
  switch (Op->Header.ElementSize) {
    case 1: {
      smin(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      smin(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      smin(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      cmgt(VTMP1.V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
      mov(VTMP2.V2D(), GetSrc(Op->Vector1.ID()).V2D());
      bif(VTMP2.V16B(), GetSrc(Op->Vector2.ID()).V16B(), VTMP1.V16B());
      mov(GetDst(Node).V2D(), VTMP2.V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VUMax) {
  auto Op = IROp->C<IR::IROp_VUMax>();
  switch (Op->Header.ElementSize) {
    case 1: {
      umax(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      umax(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      umax(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      cmhi(VTMP1.V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
      mov(VTMP2.V2D(), GetSrc(Op->Vector1.ID()).V2D());
      bit(VTMP2.V16B(), GetSrc(Op->Vector2.ID()).V16B(), VTMP1.V16B());
      mov(GetDst(Node).V2D(), VTMP2.V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VSMax) {
  auto Op = IROp->C<IR::IROp_VSMax>();
  switch (Op->Header.ElementSize) {
    case 1: {
      smax(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      smax(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      smax(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      cmgt(VTMP1.V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
      mov(VTMP2.V2D(), GetSrc(Op->Vector1.ID()).V2D());
      bit(VTMP2.V16B(), GetSrc(Op->Vector2.ID()).V16B(), VTMP1.V16B());
      mov(GetDst(Node).V2D(), VTMP2.V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VZip) {
  auto Op = IROp->C<IR::IROp_VZip>();
  const uint8_t OpSize = IROp->Size;
  if (OpSize == 8) {
    switch (Op->Header.ElementSize) {
      case 1: {
        zip1(GetDst(Node).V8B(), GetSrc(Op->VectorLower.ID()).V8B(), GetSrc(Op->VectorUpper.ID()).V8B());
      break;
      }
      case 2: {
        zip1(GetDst(Node).V4H(), GetSrc(Op->VectorLower.ID()).V4H(), GetSrc(Op->VectorUpper.ID()).V4H());
      break;
      }
      case 4: {
        zip1(GetDst(Node).V2S(), GetSrc(Op->VectorLower.ID()).V2S(), GetSrc(Op->VectorUpper.ID()).V2S());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    switch (Op->Header.ElementSize) {
      case 1: {
        zip1(GetDst(Node).V16B(), GetSrc(Op->VectorLower.ID()).V16B(), GetSrc(Op->VectorUpper.ID()).V16B());
      break;
      }
      case 2: {
        zip1(GetDst(Node).V8H(), GetSrc(Op->VectorLower.ID()).V8H(), GetSrc(Op->VectorUpper.ID()).V8H());
      break;
      }
      case 4: {
        zip1(GetDst(Node).V4S(), GetSrc(Op->VectorLower.ID()).V4S(), GetSrc(Op->VectorUpper.ID()).V4S());
      break;
      }
      case 8: {
        zip1(GetDst(Node).V2D(), GetSrc(Op->VectorLower.ID()).V2D(), GetSrc(Op->VectorUpper.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VZip2) {
  auto Op = IROp->C<IR::IROp_VZip2>();
  const uint8_t OpSize = IROp->Size;
  if (OpSize == 8) {
    switch (Op->Header.ElementSize) {
    case 1: {
      zip2(GetDst(Node).V8B(), GetSrc(Op->VectorLower.ID()).V8B(), GetSrc(Op->VectorUpper.ID()).V8B());
    break;
    }
    case 2: {
      zip2(GetDst(Node).V4H(), GetSrc(Op->VectorLower.ID()).V4H(), GetSrc(Op->VectorUpper.ID()).V4H());
    break;
    }
    case 4: {
      zip2(GetDst(Node).V2S(), GetSrc(Op->VectorLower.ID()).V2S(), GetSrc(Op->VectorUpper.ID()).V2S());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    switch (Op->Header.ElementSize) {
    case 1: {
      zip2(GetDst(Node).V16B(), GetSrc(Op->VectorLower.ID()).V16B(), GetSrc(Op->VectorUpper.ID()).V16B());
    break;
    }
    case 2: {
      zip2(GetDst(Node).V8H(), GetSrc(Op->VectorLower.ID()).V8H(), GetSrc(Op->VectorUpper.ID()).V8H());
    break;
    }
    case 4: {
      zip2(GetDst(Node).V4S(), GetSrc(Op->VectorLower.ID()).V4S(), GetSrc(Op->VectorUpper.ID()).V4S());
    break;
    }
    case 8: {
      zip2(GetDst(Node).V2D(), GetSrc(Op->VectorLower.ID()).V2D(), GetSrc(Op->VectorUpper.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VUnZip) {
  auto Op = IROp->C<IR::IROp_VUnZip>();
  const uint8_t OpSize = IROp->Size;
  if (OpSize == 8) {
    switch (Op->Header.ElementSize) {
      case 1: {
        uzp1(GetDst(Node).V8B(), GetSrc(Op->VectorLower.ID()).V8B(), GetSrc(Op->VectorUpper.ID()).V8B());
      break;
      }
      case 2: {
        uzp1(GetDst(Node).V4H(), GetSrc(Op->VectorLower.ID()).V4H(), GetSrc(Op->VectorUpper.ID()).V4H());
      break;
      }
      case 4: {
        uzp1(GetDst(Node).V2S(), GetSrc(Op->VectorLower.ID()).V2S(), GetSrc(Op->VectorUpper.ID()).V2S());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    switch (Op->Header.ElementSize) {
      case 1: {
        uzp1(GetDst(Node).V16B(), GetSrc(Op->VectorLower.ID()).V16B(), GetSrc(Op->VectorUpper.ID()).V16B());
      break;
      }
      case 2: {
        uzp1(GetDst(Node).V8H(), GetSrc(Op->VectorLower.ID()).V8H(), GetSrc(Op->VectorUpper.ID()).V8H());
      break;
      }
      case 4: {
        uzp1(GetDst(Node).V4S(), GetSrc(Op->VectorLower.ID()).V4S(), GetSrc(Op->VectorUpper.ID()).V4S());
      break;
      }
      case 8: {
        uzp1(GetDst(Node).V2D(), GetSrc(Op->VectorLower.ID()).V2D(), GetSrc(Op->VectorUpper.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VUnZip2) {
  auto Op = IROp->C<IR::IROp_VUnZip2>();
  uint8_t OpSize = IROp->Size;
  if (OpSize == 8) {
    switch (Op->Header.ElementSize) {
    case 1: {
      uzp2(GetDst(Node).V8B(), GetSrc(Op->VectorLower.ID()).V8B(), GetSrc(Op->VectorUpper.ID()).V8B());
    break;
    }
    case 2: {
      uzp2(GetDst(Node).V4H(), GetSrc(Op->VectorLower.ID()).V4H(), GetSrc(Op->VectorUpper.ID()).V4H());
    break;
    }
    case 4: {
      uzp2(GetDst(Node).V2S(), GetSrc(Op->VectorLower.ID()).V2S(), GetSrc(Op->VectorUpper.ID()).V2S());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    switch (Op->Header.ElementSize) {
    case 1: {
      uzp2(GetDst(Node).V16B(), GetSrc(Op->VectorLower.ID()).V16B(), GetSrc(Op->VectorUpper.ID()).V16B());
    break;
    }
    case 2: {
      uzp2(GetDst(Node).V8H(), GetSrc(Op->VectorLower.ID()).V8H(), GetSrc(Op->VectorUpper.ID()).V8H());
    break;
    }
    case 4: {
      uzp2(GetDst(Node).V4S(), GetSrc(Op->VectorLower.ID()).V4S(), GetSrc(Op->VectorUpper.ID()).V4S());
    break;
    }
    case 8: {
      uzp2(GetDst(Node).V2D(), GetSrc(Op->VectorLower.ID()).V2D(), GetSrc(Op->VectorUpper.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VBSL) {
  auto Op = IROp->C<IR::IROp_VBSL>();
  if (IROp->Size == 16) {
    mov(VTMP1.V16B(), GetSrc(Op->VectorMask.ID()).V16B());
    bsl(VTMP1.V16B(), GetSrc(Op->VectorTrue.ID()).V16B(), GetSrc(Op->VectorFalse.ID()).V16B());
    mov(GetDst(Node).V16B(), VTMP1.V16B());
  }
  else {
    mov(VTMP1.V8B(), GetSrc(Op->VectorMask.ID()).V8B());
    bsl(VTMP1.V8B(), GetSrc(Op->VectorTrue.ID()).V8B(), GetSrc(Op->VectorFalse.ID()).V8B());
    mov(GetDst(Node).V8B(), VTMP1.V8B());
  }
}

DEF_OP(VCMPEQ) {
  auto Op = IROp->C<IR::IROp_VCMPEQ>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        cmeq(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        cmeq(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 1: {
        cmeq(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
      break;
      }
      case 2: {
        cmeq(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
      break;
      }
      case 4: {
        cmeq(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        cmeq(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VCMPEQZ) {
  auto Op = IROp->C<IR::IROp_VCMPEQZ>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        cmeq(GetDst(Node).S(), GetSrc(Op->Vector.ID()).S(), 0);
      break;
      }
      case 8: {
        cmeq(GetDst(Node).D(), GetSrc(Op->Vector.ID()).D(), 0);
      break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 1: {
        cmeq(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), 0);
      break;
      }
      case 2: {
        cmeq(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), 0);
      break;
      }
      case 4: {
        cmeq(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), 0);
      break;
      }
      case 8: {
        cmeq(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), 0);
      break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VCMPGT) {
  auto Op = IROp->C<IR::IROp_VCMPGT>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        cmgt(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        cmgt(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 1: {
        cmgt(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
      break;
      }
      case 2: {
        cmgt(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
      break;
      }
      case 4: {
        cmgt(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        cmgt(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VCMPGTZ) {
  auto Op = IROp->C<IR::IROp_VCMPGTZ>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        cmgt(GetDst(Node).S(), GetSrc(Op->Vector.ID()).S(), 0);
      break;
      }
      case 8: {
        cmgt(GetDst(Node).D(), GetSrc(Op->Vector.ID()).D(), 0);
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 1: {
        cmgt(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), 0);
      break;
      }
      case 2: {
        cmgt(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), 0);
      break;
      }
      case 4: {
        cmgt(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), 0);
      break;
      }
      case 8: {
        cmgt(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), 0);
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VCMPLTZ) {
  auto Op = IROp->C<IR::IROp_VCMPLTZ>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        cmlt(GetDst(Node).S(), GetSrc(Op->Vector.ID()).S(), 0);
      break;
      }
      case 8: {
        cmlt(GetDst(Node).D(), GetSrc(Op->Vector.ID()).D(), 0);
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 1: {
        cmlt(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), 0);
      break;
      }
      case 2: {
        cmlt(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), 0);
      break;
      }
      case 4: {
        cmlt(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), 0);
      break;
      }
      case 8: {
        cmlt(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), 0);
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFCMPEQ) {
  auto Op = IROp->C<IR::IROp_VFCMPEQ>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmeq(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        fcmeq(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 2: {
        fcmeq(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
      break;
      }
      case 4: {
        fcmeq(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        fcmeq(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFCMPNEQ) {
  auto Op = IROp->C<IR::IROp_VFCMPNEQ>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmeq(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        fcmeq(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
    mvn(GetDst(Node).V8B(), GetDst(Node).V8B());
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 2: {
        fcmeq(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
      break;
      }
      case 4: {
        fcmeq(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        fcmeq(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
    mvn(GetDst(Node).V16B(), GetDst(Node).V16B());
  }
}

DEF_OP(VFCMPLT) {
  auto Op = IROp->C<IR::IROp_VFCMPLT>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmgt(GetDst(Node).S(), GetSrc(Op->Vector2.ID()).S(), GetSrc(Op->Vector1.ID()).S());
      break;
      }
      case 8: {
        fcmgt(GetDst(Node).D(), GetSrc(Op->Vector2.ID()).D(), GetSrc(Op->Vector1.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 2: {
        fcmgt(GetDst(Node).V8H(), GetSrc(Op->Vector2.ID()).V8H(), GetSrc(Op->Vector1.ID()).V8H());
      break;
      }
      case 4: {
        fcmgt(GetDst(Node).V4S(), GetSrc(Op->Vector2.ID()).V4S(), GetSrc(Op->Vector1.ID()).V4S());
      break;
      }
      case 8: {
        fcmgt(GetDst(Node).V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFCMPGT) {
  auto Op = IROp->C<IR::IROp_VFCMPGT>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmgt(GetDst(Node).S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
      break;
      }
      case 8: {
        fcmgt(GetDst(Node).D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 2: {
        fcmgt(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
      break;
      }
      case 4: {
        fcmgt(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
      break;
      }
      case 8: {
        fcmgt(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFCMPLE) {
  auto Op = IROp->C<IR::IROp_VFCMPLE>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmge(GetDst(Node).S(), GetSrc(Op->Vector2.ID()).S(), GetSrc(Op->Vector1.ID()).S());
      break;
      }
      case 8: {
        fcmge(GetDst(Node).D(), GetSrc(Op->Vector2.ID()).D(), GetSrc(Op->Vector1.ID()).D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 2: {
        fcmge(GetDst(Node).V8H(), GetSrc(Op->Vector2.ID()).V8H(), GetSrc(Op->Vector1.ID()).V8H());
      break;
      }
      case 4: {
        fcmge(GetDst(Node).V4S(), GetSrc(Op->Vector2.ID()).V4S(), GetSrc(Op->Vector1.ID()).V4S());
      break;
      }
      case 8: {
        fcmge(GetDst(Node).V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFCMPORD) {
  auto Op = IROp->C<IR::IROp_VFCMPORD>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmge(VTMP1.S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
        fcmgt(VTMP2.S(), GetSrc(Op->Vector2.ID()).S(), GetSrc(Op->Vector1.ID()).S());
        orr(GetDst(Node).V8B(), VTMP1.V8B(), VTMP2.V8B());
      break;
      }
      case 8: {
        fcmge(VTMP1.D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
        fcmgt(VTMP2.D(), GetSrc(Op->Vector2.ID()).D(), GetSrc(Op->Vector1.ID()).D());
        orr(GetDst(Node).V8B(), VTMP1.V8B(), VTMP2.V8B());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 2: {
        fcmge(VTMP1.V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
        fcmgt(VTMP2.V8H(), GetSrc(Op->Vector2.ID()).V8H(), GetSrc(Op->Vector1.ID()).V8H());
        orr(GetDst(Node).V16B(), VTMP1.V16B(), VTMP2.V16B());
      break;
      }
      case 4: {
        fcmge(VTMP1.V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
        fcmgt(VTMP2.V4S(), GetSrc(Op->Vector2.ID()).V4S(), GetSrc(Op->Vector1.ID()).V4S());
        orr(GetDst(Node).V16B(), VTMP1.V16B(), VTMP2.V16B());
      break;
      }
      case 8: {
        fcmge(VTMP1.V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
        fcmgt(VTMP2.V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
        orr(GetDst(Node).V16B(), VTMP1.V16B(), VTMP2.V16B());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VFCMPUNO) {
  auto Op = IROp->C<IR::IROp_VFCMPUNO>();
  const uint8_t OpSize = IROp->Size;
  if (Op->Header.ElementSize == OpSize) {
    // Scalar
    switch (Op->Header.ElementSize) {
      case 4: {
        fcmge(VTMP1.S(), GetSrc(Op->Vector1.ID()).S(), GetSrc(Op->Vector2.ID()).S());
        fcmgt(VTMP2.S(), GetSrc(Op->Vector2.ID()).S(), GetSrc(Op->Vector1.ID()).S());
        orr(GetDst(Node).V8B(), VTMP1.V8B(), VTMP2.V8B());
        mvn(GetDst(Node).V8B(), GetDst(Node).V8B());
      break;
      }
      case 8: {
        fcmge(VTMP1.D(), GetSrc(Op->Vector1.ID()).D(), GetSrc(Op->Vector2.ID()).D());
        fcmgt(VTMP2.D(), GetSrc(Op->Vector2.ID()).D(), GetSrc(Op->Vector1.ID()).D());
        orr(GetDst(Node).V8B(), VTMP1.V8B(), VTMP2.V8B());
        mvn(GetDst(Node).V8B(), GetDst(Node).V8B());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
  else {
    // Vector
    switch (Op->Header.ElementSize) {
      case 2: {
        fcmge(VTMP1.V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
        fcmgt(VTMP2.V8H(), GetSrc(Op->Vector2.ID()).V8H(), GetSrc(Op->Vector1.ID()).V8H());
        orr(GetDst(Node).V16B(), VTMP1.V16B(), VTMP2.V16B());
        mvn(GetDst(Node).V16B(), GetDst(Node).V16B());
      break;
      }
      case 4: {
        fcmge(VTMP1.V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
        fcmgt(VTMP2.V4S(), GetSrc(Op->Vector2.ID()).V4S(), GetSrc(Op->Vector1.ID()).V4S());
        orr(GetDst(Node).V16B(), VTMP1.V16B(), VTMP2.V16B());
        mvn(GetDst(Node).V16B(), GetDst(Node).V16B());
      break;
      }
      case 8: {
        fcmge(VTMP1.V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
        fcmgt(VTMP2.V2D(), GetSrc(Op->Vector2.ID()).V2D(), GetSrc(Op->Vector1.ID()).V2D());
        orr(GetDst(Node).V16B(), VTMP1.V16B(), VTMP2.V16B());
        mvn(GetDst(Node).V16B(), GetDst(Node).V16B());
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VUShl) {
  LOGMAN_MSG_A_FMT("Unimplemented");
}

DEF_OP(VUShr) {
  LOGMAN_MSG_A_FMT("Unimplemented");
}

DEF_OP(VSShr) {
  LOGMAN_MSG_A_FMT("Unimplemented");
}

DEF_OP(VUShlS) {
  auto Op = IROp->C<IR::IROp_VUShlS>();

  switch (Op->Header.ElementSize) {
    case 1: {
      dup(VTMP1.V16B(), GetSrc(Op->ShiftScalar.ID()).V16B(), 0);
      ushl(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), VTMP1.V16B());
    break;
    }
    case 2: {
      dup(VTMP1.V8H(), GetSrc(Op->ShiftScalar.ID()).V8H(), 0);
      ushl(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), VTMP1.V8H());
    break;
    }
    case 4: {
      dup(VTMP1.V4S(), GetSrc(Op->ShiftScalar.ID()).V4S(), 0);
      ushl(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), VTMP1.V4S());
    break;
    }
    case 8: {
      dup(VTMP1.V2D(), GetSrc(Op->ShiftScalar.ID()).V2D(), 0);
      ushl(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), VTMP1.V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VUShrS) {
  auto Op = IROp->C<IR::IROp_VUShrS>();

  switch (Op->Header.ElementSize) {
    case 1: {
      dup(VTMP1.V16B(), GetSrc(Op->ShiftScalar.ID()).V16B(), 0);
      neg(VTMP1.V16B(), VTMP1.V16B());
      ushl(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), VTMP1.V16B());
    break;
    }
    case 2: {
      dup(VTMP1.V8H(), GetSrc(Op->ShiftScalar.ID()).V8H(), 0);
      neg(VTMP1.V8H(), VTMP1.V8H());
      ushl(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), VTMP1.V8H());
    break;
    }
    case 4: {
      dup(VTMP1.V4S(), GetSrc(Op->ShiftScalar.ID()).V4S(), 0);
      neg(VTMP1.V4S(), VTMP1.V4S());
      ushl(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), VTMP1.V4S());
    break;
    }
    case 8: {
      dup(VTMP1.V2D(), GetSrc(Op->ShiftScalar.ID()).V2D(), 0);
      neg(VTMP1.V2D(), VTMP1.V2D());
      ushl(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), VTMP1.V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VSShrS) {
  auto Op = IROp->C<IR::IROp_VSShrS>();

  switch (Op->Header.ElementSize) {
    case 1: {
      dup(VTMP1.V16B(), GetSrc(Op->ShiftScalar.ID()).V16B(), 0);
      neg(VTMP1.V16B(), VTMP1.V16B());
      sshl(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), VTMP1.V16B());
    break;
    }
    case 2: {
      dup(VTMP1.V8H(), GetSrc(Op->ShiftScalar.ID()).V8H(), 0);
      neg(VTMP1.V8H(), VTMP1.V8H());
      sshl(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), VTMP1.V8H());
    break;
    }
    case 4: {
      dup(VTMP1.V4S(), GetSrc(Op->ShiftScalar.ID()).V4S(), 0);
      neg(VTMP1.V4S(), VTMP1.V4S());
      sshl(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), VTMP1.V4S());
    break;
    }
    case 8: {
      dup(VTMP1.V2D(), GetSrc(Op->ShiftScalar.ID()).V2D(), 0);
      neg(VTMP1.V2D(), VTMP1.V2D());
      sshl(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), VTMP1.V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VInsElement) {
  auto Op = IROp->C<IR::IROp_VInsElement>();

  auto reg = GetSrc(Op->DestVector.ID());

  if (GetDst(Node).GetCode() != reg.GetCode()) {
    mov(VTMP1, reg);
    reg = VTMP1;
  }

  switch (Op->Header.ElementSize) {
    case 1: {
      mov(reg.V16B(), Op->DestIdx, GetSrc(Op->SrcVector.ID()).V16B(), Op->SrcIdx);
    break;
    }
    case 2: {
      mov(reg.V8H(), Op->DestIdx, GetSrc(Op->SrcVector.ID()).V8H(), Op->SrcIdx);
    break;
    }
    case 4: {
      mov(reg.V4S(), Op->DestIdx, GetSrc(Op->SrcVector.ID()).V4S(), Op->SrcIdx);
    break;
    }
    case 8: {
      mov(reg.V2D(), Op->DestIdx, GetSrc(Op->SrcVector.ID()).V2D(), Op->SrcIdx);
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }

  if (GetDst(Node).GetCode() != reg.GetCode()) {
    mov(GetDst(Node), reg);
  }
}

DEF_OP(VInsScalarElement) {
  auto Op = IROp->C<IR::IROp_VInsScalarElement>();

  auto reg = GetSrc(Op->DestVector.ID());

  if (GetDst(Node).GetCode() != reg.GetCode()) {
    mov(VTMP1, reg);
    reg = VTMP1;
  }

  switch (Op->Header.ElementSize) {
    case 1: {
      mov(reg.V16B(), Op->DestIdx, GetSrc(Op->SrcScalar.ID()).V16B(), 0);
    break;
    }
    case 2: {
      mov(reg.V8H(), Op->DestIdx, GetSrc(Op->SrcScalar.ID()).V8H(), 0);
    break;
    }
    case 4: {
      mov(reg.V4S(), Op->DestIdx, GetSrc(Op->SrcScalar.ID()).V4S(), 0);
    break;
    }
    case 8: {
      mov(reg.V2D(), Op->DestIdx, GetSrc(Op->SrcScalar.ID()).V2D(), 0);
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }

  if (GetDst(Node).GetCode() != reg.GetCode()) {
    mov(GetDst(Node), reg);
  }
}

DEF_OP(VExtractElement) {
  auto Op = IROp->C<IR::IROp_VExtractElement>();
  switch (Op->Header.Size) {
    case 1:
      mov(GetDst(Node).B(), GetSrc(Op->Vector.ID()).V16B(), Op->Index);
    break;
    case 2:
      mov(GetDst(Node).H(), GetSrc(Op->Vector.ID()).V8H(), Op->Index);
    break;
    case 4:
      mov(GetDst(Node).S(), GetSrc(Op->Vector.ID()).V4S(), Op->Index);
    break;
    case 8:
      mov(GetDst(Node).D(), GetSrc(Op->Vector.ID()).V2D(), Op->Index);
    break;
    default:  LOGMAN_MSG_A_FMT("Unhandled VExtractElement element size: {}", Op->Header.Size);
  }
}

DEF_OP(VDupElement) {
  auto Op = IROp->C<IR::IROp_VDupElement>();
  switch (Op->Header.ElementSize) {
    case 1:
      dup(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), Op->Index);
    break;
    case 2:
      dup(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), Op->Index);
    break;
    case 4:
      dup(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), Op->Index);
    break;
    case 8:
      dup(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), Op->Index);
    break;
    default:  LOGMAN_MSG_A_FMT("Unhandled VDupElement element size: {}", Op->Header.ElementSize);
  }
}

DEF_OP(VExtr) {
  auto Op = IROp->C<IR::IROp_VExtr>();
  const uint8_t OpSize = IROp->Size;

  // AArch64 ext op has bit arrangement as [Vm:Vn] so arguments need to be swapped
  auto UpperBits = GetSrc(Op->VectorLower.ID());
  auto LowerBits = GetSrc(Op->VectorUpper.ID());
  auto Index = Op->Index;

  if (Index >= OpSize) {
    // Upper bits have moved in to the lower bits
    LowerBits = UpperBits;

    // Upper bits are all now zero
    UpperBits = VTMP1;
    eor(VTMP1.V16B(), VTMP1.V16B(), VTMP1.V16B());
    Index -= OpSize;
  }

  if (OpSize == 8) {
    ext(GetDst(Node).V8B(), LowerBits.V8B(), UpperBits.V8B(), Index * Op->Header.ElementSize);
  }
  else {
    ext(GetDst(Node).V16B(), LowerBits.V16B(), UpperBits.V16B(), Index * Op->Header.ElementSize);
  }
}

DEF_OP(VSLI) {
  auto Op = IROp->C<IR::IROp_VSLI>();
  const uint8_t OpSize = IROp->Size;
  const uint8_t BitShift = Op->ByteShift * 8;
  if (BitShift < 64) {
    // Move to Pair [TMP2:TMP1]
    mov(TMP1, GetSrc(Op->Vector.ID()).V2D(), 0);
    mov(TMP2, GetSrc(Op->Vector.ID()).V2D(), 1);
    // Left shift low 64bits
    lsl(TMP3, TMP1, BitShift);

    // Extract high 64bits from [TMP2:TMP1]
    extr(TMP1, TMP2, TMP1, 64 - BitShift);

    mov(GetDst(Node).V2D(), 0, TMP3);
    mov(GetDst(Node).V2D(), 1, TMP1);
  }
  else {
    if (Op->ByteShift >= OpSize) {
      eor(GetDst(Node).V16B(), GetDst(Node).V16B(), GetDst(Node).V16B());
    }
    else {
      mov(TMP1, GetSrc(Op->Vector.ID()).V2D(), 0);
      lsl(TMP1, TMP1, BitShift - 64);
      mov(GetDst(Node).V2D(), 0, xzr);
      mov(GetDst(Node).V2D(), 1, TMP1);
    }
  }
}

DEF_OP(VSRI) {
  auto Op = IROp->C<IR::IROp_VSRI>();
  const uint8_t OpSize = IROp->Size;
  const uint8_t BitShift = Op->ByteShift * 8;
  if (BitShift < 64) {
    // Move to Pair [TMP2:TMP1]
    mov(TMP1, GetSrc(Op->Vector.ID()).V2D(), 0);
    mov(TMP2, GetSrc(Op->Vector.ID()).V2D(), 1);

    // Extract Low 64bits [TMP2:TMP2] >> BitShift
    extr(TMP1, TMP2, TMP1, BitShift);
    // Right shift high bits
    lsr(TMP2, TMP2, BitShift);

    mov(GetDst(Node).V2D(), 0, TMP1);
    mov(GetDst(Node).V2D(), 1, TMP2);
  }
  else {
    if (Op->ByteShift >= OpSize) {
      eor(GetDst(Node).V16B(), GetDst(Node).V16B(), GetDst(Node).V16B());
    }
    else {
      mov(TMP1, GetSrc(Op->Vector.ID()).V2D(), 1);
      lsr(TMP1, TMP1, BitShift - 64);
      mov(GetDst(Node).V2D(), 0, TMP1);
      mov(GetDst(Node).V2D(), 1, xzr);
    }
  }
}

DEF_OP(VUShrI) {
  auto Op = IROp->C<IR::IROp_VUShrI>();

  if (Op->BitShift >= (Op->Header.ElementSize * 8)) {
    eor(GetDst(Node).V16B(), GetDst(Node).V16B(), GetDst(Node).V16B());
  }
  else {
    switch (Op->Header.ElementSize) {
      case 1: {
        ushr(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), Op->BitShift);
      break;
      }
      case 2: {
        ushr(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), Op->BitShift);
      break;
      }
      case 4: {
        ushr(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), Op->BitShift);
      break;
      }
      case 8: {
        ushr(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), Op->BitShift);
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VSShrI) {
  auto Op = IROp->C<IR::IROp_VSShrI>();

  switch (Op->Header.ElementSize) {
    case 1: {
      sshr(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), std::min((uint8_t)(Op->Header.ElementSize * 8 - 1), Op->BitShift));
    break;
    }
    case 2: {
      sshr(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), std::min((uint8_t)(Op->Header.ElementSize * 8 - 1), Op->BitShift));
    break;
    }
    case 4: {
      sshr(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), std::min((uint8_t)(Op->Header.ElementSize * 8 - 1), Op->BitShift));
    break;
    }
    case 8: {
      sshr(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), std::min((uint8_t)(Op->Header.ElementSize * 8 - 1), Op->BitShift));
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VShlI) {
  auto Op = IROp->C<IR::IROp_VShlI>();

  if (Op->BitShift >= (Op->Header.ElementSize * 8)) {
    eor(GetDst(Node).V16B(), GetDst(Node).V16B(), GetDst(Node).V16B());
  }
  else {
    switch (Op->Header.ElementSize) {
      case 1: {
        shl(GetDst(Node).V16B(), GetSrc(Op->Vector.ID()).V16B(), Op->BitShift);
      break;
      }
      case 2: {
        shl(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8H(), Op->BitShift);
      break;
      }
      case 4: {
        shl(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4S(), Op->BitShift);
      break;
      }
      case 8: {
        shl(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2D(), Op->BitShift);
      break;
      }
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
    }
  }
}

DEF_OP(VUShrNI) {
  auto Op = IROp->C<IR::IROp_VUShrNI>();

  switch (Op->Header.ElementSize) {
    case 1: {
      shrn(GetDst(Node).V8B(), GetSrc(Op->Vector.ID()).V8H(), Op->BitShift);
    break;
    }
    case 2: {
      shrn(GetDst(Node).V4H(), GetSrc(Op->Vector.ID()).V4S(), Op->BitShift);
    break;
    }
    case 4: {
      shrn(GetDst(Node).V2S(), GetSrc(Op->Vector.ID()).V2D(), Op->BitShift);
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VUShrNI2) {
  auto Op = IROp->C<IR::IROp_VUShrNI2>();
  mov(VTMP1, GetSrc(Op->VectorLower.ID()));
  switch (Op->Header.ElementSize) {
    case 1: {
      shrn2(VTMP1.V16B(), GetSrc(Op->VectorUpper.ID()).V8H(), Op->BitShift);
    break;
    }
    case 2: {
      shrn2(VTMP1.V8H(), GetSrc(Op->VectorUpper.ID()).V4S(), Op->BitShift);
    break;
    }
    case 4: {
      shrn2(VTMP1.V4S(), GetSrc(Op->VectorUpper.ID()).V2D(), Op->BitShift);
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }

  mov(GetDst(Node), VTMP1);
}

DEF_OP(VBitcast) {
  auto Op = IROp->C<IR::IROp_VBitcast>();
  mov(GetDst(Node), GetSrc(Op->Source.ID()));
}

DEF_OP(VSXTL) {
  auto Op = IROp->C<IR::IROp_VSXTL>();
  switch (Op->Header.ElementSize) {
    case 2:
      sxtl(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8B());
    break;
    case 4:
      sxtl(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4H());
    break;
    case 8:
      sxtl(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2S());
    break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
  }
}

DEF_OP(VSXTL2) {
  auto Op = IROp->C<IR::IROp_VSXTL2>();
  switch (Op->Header.ElementSize) {
    case 2:
      sxtl2(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V16B());
    break;
    case 4:
      sxtl2(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V8H());
    break;
    case 8:
      sxtl2(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V4S());
    break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
  }
}

DEF_OP(VUXTL) {
  auto Op = IROp->C<IR::IROp_VUXTL>();
  switch (Op->Header.ElementSize) {
    case 2:
      uxtl(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V8B());
    break;
    case 4:
      uxtl(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V4H());
    break;
    case 8:
      uxtl(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V2S());
    break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
  }
}

DEF_OP(VUXTL2) {
  auto Op = IROp->C<IR::IROp_VUXTL2>();
  switch (Op->Header.ElementSize) {
    case 2:
      uxtl2(GetDst(Node).V8H(), GetSrc(Op->Vector.ID()).V16B());
    break;
    case 4:
      uxtl2(GetDst(Node).V4S(), GetSrc(Op->Vector.ID()).V8H());
    break;
    case 8:
      uxtl2(GetDst(Node).V2D(), GetSrc(Op->Vector.ID()).V4S());
    break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
  }
}

DEF_OP(VSQXTN) {
  auto Op = IROp->C<IR::IROp_VSQXTN>();
  switch (Op->Header.ElementSize) {
    case 1:
      sqxtn(GetDst(Node).V8B(), GetSrc(Op->Vector.ID()).V8H());
    break;
    case 2:
      sqxtn(GetDst(Node).V4H(), GetSrc(Op->Vector.ID()).V4S());
    break;
    case 4:
      sqxtn(GetDst(Node).V2S(), GetSrc(Op->Vector.ID()).V2D());
    break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
  }
}

DEF_OP(VSQXTN2) {
  auto Op = IROp->C<IR::IROp_VSQXTN2>();
  uint8_t OpSize = IROp->Size;
  mov(VTMP1, GetSrc(Op->VectorLower.ID()));
  if (OpSize == 8) {
    switch (Op->Header.ElementSize) {
      case 1:
        sqxtn(VTMP2.V8B(), GetSrc(Op->VectorUpper.ID()).V8H());
        ins(VTMP1.V4S(), 1, VTMP2.V4S(), 0);
      break;
      case 2:
        sqxtn(VTMP2.V4H(), GetSrc(Op->VectorUpper.ID()).V4S());
        ins(VTMP1.V4S(), 1, VTMP2.V4S(), 0);
      break;
      case 4:
        sqxtn(VTMP2.V2S(), GetSrc(Op->VectorUpper.ID()).V2D());
        ins(VTMP1.V4S(), 1, VTMP2.V4S(), 0);
      break;
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
    }
  }
  else {
    switch (Op->Header.ElementSize) {
      case 1:
        sqxtn2(VTMP1.V16B(), GetSrc(Op->VectorUpper.ID()).V8H());
      break;
      case 2:
        sqxtn2(VTMP1.V8H(), GetSrc(Op->VectorUpper.ID()).V4S());
      break;
      case 4:
        sqxtn2(VTMP1.V4S(), GetSrc(Op->VectorUpper.ID()).V2D());
      break;
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
    }
  }
  mov(GetDst(Node), VTMP1);
}

DEF_OP(VSQXTUN) {
  auto Op = IROp->C<IR::IROp_VSQXTUN>();
  switch (Op->Header.ElementSize) {
    case 1:
      sqxtun(GetDst(Node).V8B(), GetSrc(Op->Vector.ID()).V8H());
    break;
    case 2:
      sqxtun(GetDst(Node).V4H(), GetSrc(Op->Vector.ID()).V4S());
    break;
    case 4:
      sqxtun(GetDst(Node).V2S(), GetSrc(Op->Vector.ID()).V2D());
    break;
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
  }
}

DEF_OP(VSQXTUN2) {
  auto Op = IROp->C<IR::IROp_VSQXTUN2>();
  uint8_t OpSize = IROp->Size;
  mov(VTMP1, GetSrc(Op->VectorLower.ID()));
  if (OpSize == 8) {
    switch (Op->Header.ElementSize) {
      case 1:
        sqxtun(VTMP2.V8B(), GetSrc(Op->VectorUpper.ID()).V8H());
        ins(VTMP1.V4S(), 1, VTMP2.V4S(), 0);
      break;
      case 2:
        sqxtun(VTMP2.V4H(), GetSrc(Op->VectorUpper.ID()).V4S());
        ins(VTMP1.V4S(), 1, VTMP2.V4S(), 0);
      break;
      case 4:
        sqxtun(VTMP2.V2S(), GetSrc(Op->VectorUpper.ID()).V2D());
        ins(VTMP1.V4S(), 1, VTMP2.V4S(), 0);
      break;
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
    }
  }
  else {
    switch (Op->Header.ElementSize) {
      case 1:
        sqxtun2(VTMP1.V16B(), GetSrc(Op->VectorUpper.ID()).V8H());
      break;
      case 2:
        sqxtun2(VTMP1.V8H(), GetSrc(Op->VectorUpper.ID()).V4S());
      break;
      case 4:
        sqxtun2(VTMP1.V4S(), GetSrc(Op->VectorUpper.ID()).V2D());
      break;
      default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize);
    }
  }
  mov(GetDst(Node), VTMP1);
}

DEF_OP(VMul) {
  auto Op = IROp->C<IR::IROp_VUMul>();
  switch (Op->Header.ElementSize) {
    case 1: {
      mul(GetDst(Node).V16B(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 2: {
      mul(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 4: {
      mul(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    case 8: {
      mul(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2D(), GetSrc(Op->Vector2.ID()).V2D());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize); break;
  }
}

DEF_OP(VUMull) {
  auto Op = IROp->C<IR::IROp_VUMull>();
  switch (Op->Header.ElementSize) {
    case 2: {
      umull(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8B(), GetSrc(Op->Vector2.ID()).V8B());
    break;
    }
    case 4: {
      umull(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4H(), GetSrc(Op->Vector2.ID()).V4H());
    break;
    }
    case 8: {
      umull(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2S(), GetSrc(Op->Vector2.ID()).V2S());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize >> 1); break;
  }
}

DEF_OP(VSMull) {
  auto Op = IROp->C<IR::IROp_VSMull>();
  switch (Op->Header.ElementSize) {
    case 2: {
      smull(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8B(), GetSrc(Op->Vector2.ID()).V8B());
    break;
    }
    case 4: {
      smull(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4H(), GetSrc(Op->Vector2.ID()).V4H());
    break;
    }
    case 8: {
      smull(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2S(), GetSrc(Op->Vector2.ID()).V2S());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize >> 1); break;
  }
}

DEF_OP(VUMull2) {
  auto Op = IROp->C<IR::IROp_VUMull2>();
  switch (Op->Header.ElementSize) {
    case 2: {
      umull2(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 4: {
      umull2(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 8: {
      umull2(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize >> 1); break;
  }
}

DEF_OP(VSMull2) {
  auto Op = IROp->C<IR::IROp_VSMull2>();
  switch (Op->Header.ElementSize) {
    case 2: {
      smull2(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V16B(), GetSrc(Op->Vector2.ID()).V16B());
    break;
    }
    case 4: {
      smull2(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V8H(), GetSrc(Op->Vector2.ID()).V8H());
    break;
    }
    case 8: {
      smull2(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V4S(), GetSrc(Op->Vector2.ID()).V4S());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize >> 1); break;
  }
}

DEF_OP(VUABDL) {
  auto Op = IROp->C<IR::IROp_VUABDL>();
  switch (Op->Header.ElementSize) {
    case 2: {
      uabdl(GetDst(Node).V8H(), GetSrc(Op->Vector1.ID()).V8B(), GetSrc(Op->Vector2.ID()).V8B());
    break;
    }
    case 4: {
      uabdl(GetDst(Node).V4S(), GetSrc(Op->Vector1.ID()).V4H(), GetSrc(Op->Vector2.ID()).V4H());
    break;
    }
    case 8: {
      uabdl(GetDst(Node).V2D(), GetSrc(Op->Vector1.ID()).V2S(), GetSrc(Op->Vector2.ID()).V2S());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown Element Size: {}", Op->Header.ElementSize >> 1); break;
  }
}

DEF_OP(VTBL1) {
  auto Op = IROp->C<IR::IROp_VTBL1>();
  const uint8_t OpSize = IROp->Size;

  switch (OpSize) {
    case 8: {
      tbl(GetDst(Node).V8B(), GetSrc(Op->VectorTable.ID()).V16B(), GetSrc(Op->VectorIndices.ID()).V8B());
    break;
    }
    case 16: {
      tbl(GetDst(Node).V16B(), GetSrc(Op->VectorTable.ID()).V16B(), GetSrc(Op->VectorIndices.ID()).V16B());
    break;
    }
    default: LOGMAN_MSG_A_FMT("Unknown OpSize: {}", OpSize); break;
  }
}

DEF_OP(VRev64) {
  auto Op = IROp->C<IR::IROp_VRev64>();
  const uint8_t OpSize = IROp->Size;
  const uint8_t Elements = OpSize / Op->Header.ElementSize;
  // Vector
  switch (Op->Header.ElementSize) {
    case 1:
    case 2:
    case 4:
      rev64(GetDst(Node).VCast(OpSize * 8, Elements), GetSrc(Op->Vector.ID()).VCast(OpSize * 8, Elements));
      break;
    case 8:
    default: LOGMAN_MSG_A_FMT("Invalid Element Size: {}", Op->Header.ElementSize); break;
  }
}

#undef DEF_OP
void Arm64JITCore::RegisterVectorHandlers() {
#define REGISTER_OP(op, x) OpHandlers[FEXCore::IR::IROps::OP_##op] = &Arm64JITCore::Op_##x
  REGISTER_OP(VECTORZERO,        VectorZero);
  REGISTER_OP(VECTORIMM,         VectorImm);
  REGISTER_OP(SPLATVECTOR2,      SplatVector2);
  REGISTER_OP(SPLATVECTOR4,      SplatVector4);
  REGISTER_OP(VMOV,              VMov);
  REGISTER_OP(VAND,              VAnd);
  REGISTER_OP(VBIC,              VBic);
  REGISTER_OP(VOR,               VOr);
  REGISTER_OP(VXOR,              VXor);
  REGISTER_OP(VADD,              VAdd);
  REGISTER_OP(VSUB,              VSub);
  REGISTER_OP(VUQADD,            VUQAdd);
  REGISTER_OP(VUQSUB,            VUQSub);
  REGISTER_OP(VSQADD,            VSQAdd);
  REGISTER_OP(VSQSUB,            VSQSub);
  REGISTER_OP(VADDP,             VAddP);
  REGISTER_OP(VADDV,             VAddV);
  REGISTER_OP(VUMINV,            VUMinV);
  REGISTER_OP(VURAVG,            VURAvg);
  REGISTER_OP(VABS,              VAbs);
  REGISTER_OP(VPOPCOUNT,         VPopcount);
  REGISTER_OP(VFADD,             VFAdd);
  REGISTER_OP(VFADDP,            VFAddP);
  REGISTER_OP(VFSUB,             VFSub);
  REGISTER_OP(VFMUL,             VFMul);
  REGISTER_OP(VFDIV,             VFDiv);
  REGISTER_OP(VFMIN,             VFMin);
  REGISTER_OP(VFMAX,             VFMax);
  REGISTER_OP(VFRECP,            VFRecp);
  REGISTER_OP(VFSQRT,            VFSqrt);
  REGISTER_OP(VFRSQRT,           VFRSqrt);
  REGISTER_OP(VNEG,              VNeg);
  REGISTER_OP(VFNEG,             VFNeg);
  REGISTER_OP(VNOT,              VNot);
  REGISTER_OP(VUMIN,             VUMin);
  REGISTER_OP(VSMIN,             VSMin);
  REGISTER_OP(VUMAX,             VUMax);
  REGISTER_OP(VSMAX,             VSMax);
  REGISTER_OP(VZIP,              VZip);
  REGISTER_OP(VZIP2,             VZip2);
  REGISTER_OP(VUNZIP,            VUnZip);
  REGISTER_OP(VUNZIP2,           VUnZip2);
  REGISTER_OP(VBSL,              VBSL);
  REGISTER_OP(VCMPEQ,            VCMPEQ);
  REGISTER_OP(VCMPEQZ,           VCMPEQZ);
  REGISTER_OP(VCMPGT,            VCMPGT);
  REGISTER_OP(VCMPGTZ,           VCMPGTZ);
  REGISTER_OP(VCMPLTZ,           VCMPLTZ);
  REGISTER_OP(VFCMPEQ,           VFCMPEQ);
  REGISTER_OP(VFCMPNEQ,          VFCMPNEQ);
  REGISTER_OP(VFCMPLT,           VFCMPLT);
  REGISTER_OP(VFCMPGT,           VFCMPGT);
  REGISTER_OP(VFCMPLE,           VFCMPLE);
  REGISTER_OP(VFCMPORD,          VFCMPORD);
  REGISTER_OP(VFCMPUNO,          VFCMPUNO);
  REGISTER_OP(VUSHL,             VUShl);
  REGISTER_OP(VUSHR,             VUShr);
  REGISTER_OP(VSSHR,             VSShr);
  REGISTER_OP(VUSHLS,            VUShlS);
  REGISTER_OP(VUSHRS,            VUShrS);
  REGISTER_OP(VSSHRS,            VSShrS);
  REGISTER_OP(VINSELEMENT,       VInsElement);
  REGISTER_OP(VINSSCALARELEMENT, VInsScalarElement);
  REGISTER_OP(VEXTRACTELEMENT,   VExtractElement);
  REGISTER_OP(VDUPELEMENT,       VDupElement);
  REGISTER_OP(VEXTR,             VExtr);
  REGISTER_OP(VSLI,              VSLI);
  REGISTER_OP(VSRI,              VSRI);
  REGISTER_OP(VUSHRI,            VUShrI);
  REGISTER_OP(VSSHRI,            VSShrI);
  REGISTER_OP(VSHLI,             VShlI);
  REGISTER_OP(VUSHRNI,           VUShrNI);
  REGISTER_OP(VUSHRNI2,          VUShrNI2);
  REGISTER_OP(VBITCAST,          VBitcast);
  REGISTER_OP(VSXTL,             VSXTL);
  REGISTER_OP(VSXTL2,            VSXTL2);
  REGISTER_OP(VUXTL,             VUXTL);
  REGISTER_OP(VUXTL2,            VUXTL2);
  REGISTER_OP(VSQXTN,            VSQXTN);
  REGISTER_OP(VSQXTN2,           VSQXTN2);
  REGISTER_OP(VSQXTUN,           VSQXTUN);
  REGISTER_OP(VSQXTUN2,          VSQXTUN2);
  REGISTER_OP(VUMUL,             VMul);
  REGISTER_OP(VSMUL,             VMul);
  REGISTER_OP(VUMULL,            VUMull);
  REGISTER_OP(VSMULL,            VSMull);
  REGISTER_OP(VUMULL2,           VUMull2);
  REGISTER_OP(VSMULL2,           VSMull2);
  REGISTER_OP(VUABDL,            VUABDL);
  REGISTER_OP(VTBL1,             VTBL1);
  REGISTER_OP(VREV64,            VRev64);
#undef REGISTER_OP
}
}

