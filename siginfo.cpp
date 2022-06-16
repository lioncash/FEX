#include <cstddef>
#include <cstdlib>
#include <sys/mman.h>
#include <sys/signal.h>
#include <stdio.h>
#include <cstdint>
#include <string.h>
#include <asm/ucontext.h>
#include <sys/time.h>
#include <signal.h>

constexpr uint64_t OFFSET       = 0x1010101010101010ULL;
constexpr uint64_t EXPECTED_RAX = 0x1112131415161718ULL;
constexpr uint64_t EXPECTED_RBX = EXPECTED_RAX + OFFSET;
constexpr uint64_t EXPECTED_RCX = EXPECTED_RBX + OFFSET;
constexpr uint64_t EXPECTED_RDX = EXPECTED_RCX + OFFSET;
constexpr uint64_t EXPECTED_RSI = EXPECTED_RDX + OFFSET;
constexpr uint64_t EXPECTED_RDI = EXPECTED_RSI + OFFSET;
constexpr uint64_t EXPECTED_RBP = EXPECTED_RDI + OFFSET;
constexpr uint64_t EXPECTED_RSP = EXPECTED_RBP + OFFSET;
constexpr uint64_t EXPECTED_R8  = EXPECTED_RSP + OFFSET;
constexpr uint64_t EXPECTED_R9  = EXPECTED_R8 + OFFSET;
constexpr uint64_t EXPECTED_R10 = EXPECTED_R9 + OFFSET;
constexpr uint64_t EXPECTED_R11 = EXPECTED_R10 + OFFSET;
constexpr uint64_t EXPECTED_R12 = EXPECTED_R11 + OFFSET;
constexpr uint64_t EXPECTED_R13 = EXPECTED_R12 + OFFSET;
constexpr uint64_t EXPECTED_R14 = EXPECTED_R13 + OFFSET;
constexpr uint64_t EXPECTED_R15 = EXPECTED_R14 + OFFSET;

static uint32_t TestXMM[16][8] = {
  {1, 2, 3, 4, 5, 6, 7, 8},
  {9, 10, 11, 12, 13, 14, 15, 16},
  {17, 18, 19, 20, 21, 22, 23, 24},
  {25, 26, 27, 28, 29, 30, 31, 32},
  {33, 34, 35, 36, 37, 38, 39, 40},
  {41, 42, 43, 44, 45, 46, 47, 48},
  {49, 50, 51, 52, 53, 54, 55, 56},
  {57, 58, 59, 60, 61, 62, 63, 64},
  {65, 66, 67, 68, 69, 70, 71, 72},
  {73, 74, 75, 76, 77, 78, 79, 80},
  {81, 82, 83, 84, 85, 86, 87, 88},
  {89, 90, 91, 92, 93, 94, 95, 96},
  {97, 98, 99, 100, 101, 102, 103, 104},
  {105, 106, 107, 108, 109, 110, 111, 112},
  {113, 114, 115, 116, 117, 118, 119, 120},
  {121, 122, 123, 124, 125, 126, 127, 128}
};

volatile bool ready = false;

#if 1
__attribute__((naked))
static void DoSetupAndFault() {
  __asm__ __volatile__(R"(
  .intel_syntax noprefix
#  mov rax, %[EXPECTED_RAX]
  mov rbx, %[EXPECTED_RBX]
  mov rcx, %[EXPECTED_RCX]
  mov rdx, %[EXPECTED_RDX]
  mov rsi, %[EXPECTED_RSI]
  mov rdi, %[EXPECTED_RDI]
  mov rbp, %[EXPECTED_RBP]
  mov rsp, %[EXPECTED_RSP]
  mov r8,  %[EXPECTED_R8]
  mov r9,  %[EXPECTED_R9]
  mov r10, %[EXPECTED_R10]
  mov r11, %[EXPECTED_R11]
  mov r12, %[EXPECTED_R12]
  mov r13, %[EXPECTED_R13]
  mov r14, %[EXPECTED_R14]
  mov r15, %[EXPECTED_R15]

  vmovaps ymm0, %[XMM0_OFF]  + (32 * 0)
  movaps xmm1, %[XMM0_OFF]  + (32 * 1)
  movaps xmm2, %[XMM0_OFF]  + (32 * 2)
  movaps xmm3, %[XMM0_OFF]  + (32 * 3)
  movaps xmm4, %[XMM0_OFF]  + (32 * 4)
  movaps xmm5, %[XMM0_OFF]  + (32 * 5)
  movaps xmm6, %[XMM0_OFF]  + (32 * 6)
  movaps xmm7, %[XMM0_OFF]  + (32 * 7)
  movaps xmm8, %[XMM0_OFF]  + (32 * 8)
  movaps xmm9, %[XMM0_OFF]  + (32 * 9)
  movaps xmm10, %[XMM0_OFF] + (32 * 10)
  movaps xmm11, %[XMM0_OFF] + (32 * 11)
  movaps xmm12, %[XMM0_OFF] + (32 * 12)
  movaps xmm13, %[XMM0_OFF] + (32 * 13)
  movaps xmm14, %[XMM0_OFF] + (32 * 14)
  movaps xmm15, %[XMM0_OFF] + (32 * 15)

  movdq2q mm0, xmm0
  movdq2q mm1, xmm1
  movdq2q mm2, xmm2
  movdq2q mm3, xmm3
  movdq2q mm4, xmm4
  movdq2q mm5, xmm5
  movdq2q mm6, xmm6
  movdq2q mm7, xmm7

  mov rbx, -1
  mov %[ready], bl
# Do fault
# mov [0], eax;
  1:
  jmp 1b

  )"
  :
  :
  [EXPECTED_RAX] "i" (EXPECTED_RAX),
  [EXPECTED_RBX] "i" (EXPECTED_RBX),
  [EXPECTED_RCX] "i" (EXPECTED_RCX),
  [EXPECTED_RDX] "i" (EXPECTED_RDX),
  [EXPECTED_RSI] "i" (EXPECTED_RSI),
  [EXPECTED_RDI] "i" (EXPECTED_RDI),
  [EXPECTED_RBP] "i" (EXPECTED_RBP),
  [EXPECTED_RSP] "i" (EXPECTED_RSP),
  [EXPECTED_R8]  "i" (EXPECTED_R8),
  [EXPECTED_R9]  "i" (EXPECTED_R9),
  [EXPECTED_R10] "i" (EXPECTED_R10),
  [EXPECTED_R11] "i" (EXPECTED_R11),
  [EXPECTED_R12] "i" (EXPECTED_R12),
  [EXPECTED_R13] "i" (EXPECTED_R13),
  [EXPECTED_R14] "i" (EXPECTED_R14),
  [EXPECTED_R15] "i" (EXPECTED_R15),
  [XMM0_OFF] "m" (TestXMM[0]),
  [ready] "m" (ready)
  );
}
#else
__attribute__((naked))
static void DoSetupAndFault() {
  __asm__ __volatile__(R"(
  .intel_syntax noprefix

  vmovaps ymm0, %[XMM0_OFF] + (16 * 0)
  movaps xmm1, %[XMM0_OFF] + (16 * 1)
  movaps xmm2, %[XMM0_OFF] + (16 * 2)
  movaps xmm3, %[XMM0_OFF] + (16 * 3)
  movaps xmm4, %[XMM0_OFF] + (16 * 4)
  movaps xmm5, %[XMM0_OFF] + (16 * 5)
  movaps xmm6, %[XMM0_OFF] + (16 * 6)
  movaps xmm7, %[XMM0_OFF] + (16 * 7)

  movdq2q mm0, xmm0
  movdq2q mm1, xmm1
  movdq2q mm2, xmm2
  movdq2q mm3, xmm3
  movdq2q mm4, xmm4
  movdq2q mm5, xmm5
  movdq2q mm6, xmm6
  movdq2q mm7, xmm7

# Setup GPRs after other things since they rely on eax
  #mov eax, %[EXPECTED_RAX]
  mov ebx, %[EXPECTED_RBX]
  mov ecx, %[EXPECTED_RCX]
  mov edx, %[EXPECTED_RDX]
  mov esi, %[EXPECTED_RSI]
  mov edi, %[EXPECTED_RDI]
  mov ebp, %[EXPECTED_RBP]
  mov esp, %[EXPECTED_RSP]


  mov ebx, -1
  mov %[ready], bl
# Do fault
# mov [0], eax;
  1:
  jmp 1b

  )"
  ::
  [EXPECTED_RAX] "i" ((uint32_t)EXPECTED_RAX),
  [EXPECTED_RBX] "i" ((uint32_t)EXPECTED_RBX),
  [EXPECTED_RCX] "i" ((uint32_t)EXPECTED_RCX),
  [EXPECTED_RDX] "i" ((uint32_t)EXPECTED_RDX),
  [EXPECTED_RSI] "i" ((uint32_t)EXPECTED_RSI),
  [EXPECTED_RDI] "i" ((uint32_t)EXPECTED_RDI),
  [EXPECTED_RBP] "i" ((uint32_t)EXPECTED_RBP),
  [EXPECTED_RSP] "i" ((uint32_t)EXPECTED_RSP),
  [XMM0_OFF] "m" (TestXMM[0]),
  [ready] "m" (ready)
  );
}
#endif

constexpr uint64_t NumFaults = 2;
static uint64_t HandledFaults = 0;

static void handler(int signal, siginfo_t *siginfo, void* context) {
  if (!ready) return;
  ucontext_t* _context = (ucontext_t*)context;
  auto mctx = &_context->uc_mcontext;
  fprintf(stderr, "We got to the handler: %p\n", context);
  fprintf(stderr, "offsetof uc_flags: %d\n",  offsetof(struct ucontext_t, uc_flags));
  fprintf(stderr, "GPR State:\n");
#if 1
  fprintf(stderr, "\tRAX: 0x%016llx: %s\n", mctx->gregs[REG_RAX], mctx->gregs[REG_RAX] != EXPECTED_RAX ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tRBX: 0x%016llx: %s\n", mctx->gregs[REG_RBX], mctx->gregs[REG_RBX] != EXPECTED_RBX ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tRCX: 0x%016llx: %s\n", mctx->gregs[REG_RCX], mctx->gregs[REG_RCX] != EXPECTED_RCX ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tRDX: 0x%016llx: %s\n", mctx->gregs[REG_RDX], mctx->gregs[REG_RDX] != EXPECTED_RDX ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tRSI: 0x%016llx: %s\n", mctx->gregs[REG_RSI], mctx->gregs[REG_RSI] != EXPECTED_RSI ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tRDI: 0x%016llx: %s\n", mctx->gregs[REG_RDI], mctx->gregs[REG_RDI] != EXPECTED_RDI ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tRBP: 0x%016llx: %s\n", mctx->gregs[REG_RBP], mctx->gregs[REG_RBP] != EXPECTED_RBP ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tRSP: 0x%016llx: %s\n", mctx->gregs[REG_RSP], mctx->gregs[REG_RSP] != EXPECTED_RSP ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tR8:  0x%016llx: %s\n", mctx->gregs[REG_R8], mctx->gregs[REG_R8] != EXPECTED_R8 ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tR9:  0x%016llx: %s\n", mctx->gregs[REG_R9], mctx->gregs[REG_R9] != EXPECTED_R9 ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tR10: 0x%016llx: %s\n", mctx->gregs[REG_R10], mctx->gregs[REG_R10] != EXPECTED_R10 ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tR11: 0x%016llx: %s\n", mctx->gregs[REG_R11], mctx->gregs[REG_R11] != EXPECTED_R11 ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tR12: 0x%016llx: %s\n", mctx->gregs[REG_R12], mctx->gregs[REG_R12] != EXPECTED_R12 ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tR13: 0x%016llx: %s\n", mctx->gregs[REG_R13], mctx->gregs[REG_R13] != EXPECTED_R13 ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tR14: 0x%016llx: %s\n", mctx->gregs[REG_R14], mctx->gregs[REG_R14] != EXPECTED_R14 ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tR15: 0x%016llx: %s\n", mctx->gregs[REG_R15], mctx->gregs[REG_R15] != EXPECTED_R15 ? "@@@@ FAIL @@@@" : "Pass");
#else
  fprintf(stderr, "\tEAX: 0x%08x: %s\n", mctx->gregs[REG_EAX], mctx->gregs[REG_EAX] != (uint32_t)EXPECTED_RAX ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tEBX: 0x%08x: %s\n", mctx->gregs[REG_EBX], mctx->gregs[REG_EBX] != (uint32_t)EXPECTED_RBX ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tECX: 0x%08x: %s\n", mctx->gregs[REG_ECX], mctx->gregs[REG_ECX] != (uint32_t)EXPECTED_RCX ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tEDX: 0x%08x: %s\n", mctx->gregs[REG_EDX], mctx->gregs[REG_EDX] != (uint32_t)EXPECTED_RDX ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tESI: 0x%08x: %s\n", mctx->gregs[REG_ESI], mctx->gregs[REG_ESI] != (uint32_t)EXPECTED_RSI ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tEDI: 0x%08x: %s\n", mctx->gregs[REG_EDI], mctx->gregs[REG_EDI] != (uint32_t)EXPECTED_RDI ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tEBP: 0x%08x: %s\n", mctx->gregs[REG_EBP], mctx->gregs[REG_EBP] != (uint32_t)EXPECTED_RBP ? "@@@@ FAIL @@@@" : "Pass");
  fprintf(stderr, "\tESP: 0x%08x: %s\n", mctx->gregs[REG_ESP], mctx->gregs[REG_ESP] != (uint32_t)EXPECTED_RSP ? "@@@@ FAIL @@@@" : "Pass");
#endif

  struct __attribute__((packed)) fpx_sw_bytes {
      // If magic1 is set to FP_XSTATE_MAGIC1, then the encompassing
      // frame is an xstate frame. If 0, then it's a legacy frame.
      uint32_t magic1;

      // Total size of the fpstate area
      // - magic1 = 0                -> sizeof(fpstate)
      // - magic1 = FP_XSTATE_MAGIC1 -> sizeof(xstate) + extensions (if any)
      uint32_t extended_size;

      // Feature bitmask describing supported features.
      uint64_t xfeatures;

      // Actual XSAVE state size, based on above xfeatures
      uint32_t xstate_size;

      // Reserved data
      uint32_t padding[7];
    };
    struct __attribute__((packed)) _libc_fpstate {
      // This is in FXSAVE format
      uint16_t fcw;
      uint16_t fsw;
      uint16_t ftw;
      uint16_t fop;
      uint64_t fip;
      uint64_t fdp;
      uint32_t mxcsr;
      uint32_t mxcsr_mask;
      __uint128_t _st[8];
      __uint128_t _xmm[16];
      uint32_t _res[12];
      
      // Linux uses 12 of the bytes relegated for software purposes
      // to store info describing any existing XSAVE context data.
      fpx_sw_bytes sw_reserved;
    };
    
    struct __attribute__((packed)) xstate_header {
      uint64_t xfeatures;
      uint64_t reserved1[2];
      uint64_t reserved2[5];
    };
    static_assert(sizeof(xstate_header) == 64);

    struct __attribute__((packed)) ymmh_state {
      __uint128_t ymmh_space[16];
    };
    static_assert(sizeof(ymmh_state) == 256);

    /**
     * Extended state that includes both the main fpstate
     * and the extended state.
     */
    struct __attribute__((packed)) xstate_str {
      _libc_fpstate fpstate;
      xstate_header xstate_hdr;
      ymmh_state ymmh;
    };

  fprintf(stderr, "XMM state:\n");
  auto PassesXMM = [mctx](size_t i, auto In, auto Expected) -> bool {
    auto* xstate = (xstate_str*)mctx->fpregs;

    uint32_t buff[4];
    memcpy(&buff, &xstate->ymmh.ymmh_space[i], sizeof(__uint128_t));

    return In.element[0] == Expected[0] &&
           In.element[1] == Expected[1] &&
           In.element[2] == Expected[2] &&
           In.element[3] == Expected[3] &&
           buff[0]       == Expected[4] &&
           buff[1]       == Expected[5] &&
           buff[2]       == Expected[6] &&
           buff[3]       == Expected[7];
  };

  if ((_context->uc_flags & UC_FP_XSTATE) != UC_FP_XSTATE) {
    fprintf(stderr, "context claiming it doesn't support UC_FP_XSTATE?! 0x%lx\n", _context->uc_flags);
    exit(-1);
  }

#if 1
  size_t NumXMM = 16;
  for (unsigned i = 0; i < NumXMM; ++i) {
    auto* xstate = (xstate_str*)mctx->fpregs;

    uint32_t buff[4];
    memcpy(&buff, &xstate->ymmh.ymmh_space[i], sizeof(__uint128_t));

    fprintf(stderr, "\tXMM%02d: 0x%08x'%08x'%08x'%08x 0x%08x'%08x'%08x'%08x %s\n",
      i,
      mctx->fpregs->_xmm[i].element[0],
      mctx->fpregs->_xmm[i].element[1],
      mctx->fpregs->_xmm[i].element[2],
      mctx->fpregs->_xmm[i].element[3],
      buff[0],
      buff[1],
      buff[2],
      buff[3],
      PassesXMM(i, mctx->fpregs->_xmm[i], TestXMM[i]) ? "Pass" : "@@@@ FAIL @@@@"
      );
  }
#else
  size_t NumXMM = 8;
  fprintf(stderr, "status is: 0x%08lx\n", mctx->fpregs->status);
  auto fpregs = mctx->fpregs;
  uint16_t MAGIC = mctx->fpregs->status >> 16;
  if (MAGIC == 0x0) {
    fprintf(stderr, "We have the magic range\n");
    // Now that we have the magic, the space after the regular fpstate definition is FXSR FPU environment
    struct fpxreg {
      uint32_t element[4];
    };
    struct FXSREnv {
      uint32_t fxsr_env[6]; // This is ignored
      uint32_t mxcsr;
      uint32_t reserved;
      fpxreg st[8]; // This is ignored
      fpxreg xmm[8]; // First 8 XMM registers
      uint32_t pad[44]; // Second 8 XMM registers and pad if 64bit
      uint32_t pad2[12]; // pad and fpx_sw_bytes
    };

    // Lives immediately after fpregs
    FXSREnv *env = (FXSREnv*)&fpregs[1];
    fprintf(stderr, "FXSR State:\n");
    fprintf(stderr, "\tMXCSR: 0x%08x\n", env->mxcsr);

    for (unsigned i = 0; i < NumXMM; ++i) {
      fprintf(stderr, "\tXMM%02d: 0x%08x'%08x'%08x'%08x: %s\n",
        i,
        env->xmm[i].element[0],
        env->xmm[i].element[1],
        env->xmm[i].element[2],
        env->xmm[i].element[3],
        PassesXMM(env->xmm[i], TestXMM[i]) ? "Pass" : "@@@@ FAIL @@@@"
        );
    }

  }
  else {
    fprintf(stderr, "Magic is 0x%04x?\n", MAGIC);
    exit(-1);
  }
#endif

  fprintf(stderr, "MMX state:\n");
  auto PassesMMX = [](auto In, auto Expected) -> bool {
    return (uint32_t)In == Expected[0] &&
      (uint32_t)(In >> 32) == Expected[1];
  };

  for (unsigned i = 0; i < 8; ++i) {
    uint64_t Raw{};
    memcpy(&Raw, &mctx->fpregs->_st[i], sizeof(Raw));
    fprintf(stderr, "\tMM%02d: 0x%08x'%08x: %s\n",
      i,
      (uint32_t)(Raw >> 32), (uint32_t)Raw,
      PassesMMX(Raw, TestXMM[i]) ? "Pass" : "@@@@ FAIL @@@@");
  }

  fprintf(stderr, "MMX state2:\n");

  for (unsigned i = 0; i < 8; ++i) {
    uint64_t Raw{};
    memcpy(&Raw, &_context->__fpregs_mem._st[i], sizeof(Raw));
    fprintf(stderr, "\tMM%02d: 0x%08x'%08x: %s\n",
      i,
      (uint32_t)(Raw >> 32), (uint32_t)Raw,
      PassesMMX(Raw, TestXMM[i]) ? "Pass" : "@@@@ FAIL @@@@");
  }



#if __x86_64__
  for (unsigned i = 0; i < 4; ++i) {
    fprintf(stderr, "__ssp[%d]: 0x%016llx\n", i, _context->__ssp[i]);
  }
#else
  for (unsigned i = 0; i < 4; ++i) {
    fprintf(stderr, "__ssp[%d]: 0x%08lx\n", i, _context->__ssp[i]);
  }

#endif
//  if (NumFaults == HandledFaults) {
//    exit(0);
//  }
//  ++HandledFaults;
//  DoSetupAndFault();


  setitimer(ITIMER_VIRTUAL, nullptr, nullptr);
  exit(0);
}

int main() {
  uint64_t STACKSIZE = 8 * 1024 * 1024;
  // Give ourselves an alt stack
  void *AltStack = mmap(nullptr, STACKSIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  fprintf(stderr, "Our altstack is now [%p, 0x%llx) Current Stack %p\n", AltStack, (uintptr_t)AltStack + STACKSIZE, alloca(0));

  stack_t altstack{};
  altstack.ss_sp = AltStack;
  altstack.ss_size = STACKSIZE;
  altstack.ss_flags = 0;
  sigaltstack(&altstack, nullptr);

  // Set up a handler for sigsegv
  struct sigaction act{};
  act.sa_sigaction = handler;
  act.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigaction(SIGVTALRM, &act, nullptr);

  itimerval val{};
  val.it_interval.tv_usec = 100000;
  val.it_value.tv_usec = 100000;
  setitimer(ITIMER_VIRTUAL, &val, nullptr);

  DoSetupAndFault();

  return 0;
}
