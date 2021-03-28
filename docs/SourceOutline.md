# FEXCore

## Glossary

- Splatter: a code generator backend that concaternates configurable macros instead of doing isel
- IR: Intermidiate Representation, a of storage for our high-level opcode representation
- SSA: Single Static Assignment, a form of representing IR in memory
- Basic Block: A block of instructions with no control flow, terminated by control flow
- Fragment: A Collection of basic blocks, possible an entire guest function or a fraction of it


## backend

### arm64
- [ALUOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/ALUOps.cpp): Alu ops of the arm64 splatter backend
- [AtomicOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/AtomicOps.cpp): Atomic ops of the arm64 splatter backend
- [BranchOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/BranchOps.cpp): Branch ops of the arm64 splatter backend
- [ConversionOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/ConversionOps.cpp): Conversion ops of the arm64 splatter backend
- [EncryptionOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/EncryptionOps.cpp): Encryption ops of the arm64 splatter backend
- [FlagOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/FlagOps.cpp): Flag ops of the arm64 splatter backend
- [JIT.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/JIT.cpp): Main glue logic of the arm64 splatter backend
- [JITClass.h](../External/FEXCore/Source/Interface/Core/JIT/Arm64/JITClass.h): Main glue logic of the arm64 splatter backend
- [MemoryOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/MemoryOps.cpp): Memory ops of the arm64 splatter backend
- [MiscOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/MiscOps.cpp): Misc ops of the arm64 splatter backend
- [MoveOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/MoveOps.cpp): Move ops of the arm64 splatter backend
- [VectorOps.cpp](../External/FEXCore/Source/Interface/Core/JIT/Arm64/VectorOps.cpp): Vector ops of the arm64 splatter backend



## frontend

### x86-meta-blocks
- [Frontend.cpp](../External/FEXCore/Source/Interface/Core/Frontend.cpp): Extracts instruction & block meta info, frontend mutliblock logic

### x86-to-ir
- [OpcodeDispatcher.cpp](../External/FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp): Handles x86/64 ops to IR, no-pf opt, local-flags opt



## glue
Logic that binds various parts together

### block-database
- [LookupCache.cpp](../External/FEXCore/Source/Interface/Core/LookupCache.cpp): Stores information about blocks, and provides C++ implementations to lookup the blocks

### driver
Emulation mainloop related glue logic
- [Core.cpp](../External/FEXCore/Source/Interface/Core/Core.cpp): Glues Frontend, OpDispatcher and IR Opts & Compilation, LookupCache, Dispatcher and provides the Execution loop entrypoint



## opcodes

### cpuid
- [CPUID.cpp](../External/FEXCore/Source/Interface/Core/CPUID.cpp): Handles presented capability bits for guest cpu

### dispatcher-implementations
- [OpcodeDispatcher.cpp](../External/FEXCore/Source/Interface/Core/OpcodeDispatcher.cpp): Handles x86/64 ops to IR, no-pf opt, local-flags opt

# ThunkLibs

# Scripts

# Common

# CommonCore

# Tests

# unittests

