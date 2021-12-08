#pragma once

#include "FEXCore/IR/IR.h"
#include <FEXCore/Utils/Allocator.h>
#include <FEXCore/Utils/LogManager.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <tuple>
#include <vector>
#include <istream>
#include <ostream>

namespace FEXCore::IR {
/**
 * @brief This is purely an intrusive allocator
 * This doesn't support any form of ordering at all
 * Just provides a chunk of memory for allocating IR nodes from
 *
 * Can potentially support reallocation if we are smart and make sure to invalidate anything holding a true pointer
 */
class DualIntrusiveAllocator final {
  public:
    DualIntrusiveAllocator() = delete;
    DualIntrusiveAllocator(DualIntrusiveAllocator &&) = delete;
    DualIntrusiveAllocator(size_t Size)
      : MemorySize {Size} {
      Data = reinterpret_cast<uintptr_t>(FEXCore::Allocator::malloc(Size * 2));
      List = reinterpret_cast<uintptr_t>(Data + Size);
    }


    ~DualIntrusiveAllocator() {
      FEXCore::Allocator::free(reinterpret_cast<void*>(Data));
    }

    [[nodiscard]] bool DataCheckSize(size_t Size) const {
      size_t NewOffset = DataCurrentOffset + Size;
      return NewOffset <= MemorySize;
    }

    [[nodiscard]] bool ListCheckSize(size_t Size) const {
      size_t NewOffset = ListCurrentOffset + Size;
      return NewOffset <= MemorySize;
    }

    [[nodiscard]] void *DataAllocate(size_t Size) {
      assert(DataCheckSize(Size) &&
        "Ran out of space in DualIntrusiveAllocator during allocation");
      size_t NewOffset = DataCurrentOffset + Size;
      uintptr_t NewPointer = Data + DataCurrentOffset;
      DataCurrentOffset = NewOffset;
      return reinterpret_cast<void*>(NewPointer);
    }

    [[nodiscard]] void *ListAllocate(size_t Size) {
      assert(ListCheckSize(Size) &&
        "Ran out of space in DualIntrusiveAllocator during allocation");
      size_t NewOffset = ListCurrentOffset + Size;
      uintptr_t NewPointer = List + ListCurrentOffset;
      ListCurrentOffset = NewOffset;
      return reinterpret_cast<void*>(NewPointer);
    }

    [[nodiscard]] size_t DataSize() const { return DataCurrentOffset; }
    [[nodiscard]] size_t DataBackingSize() const { return MemorySize; }

    [[nodiscard]] size_t ListSize() const { return ListCurrentOffset; }
    [[nodiscard]] size_t ListBackingSize() const { return MemorySize; }

    [[nodiscard]] uintptr_t DataBegin() const { return Data; }
    [[nodiscard]] uintptr_t ListBegin() const { return List; }

    void Reset() { DataCurrentOffset = 0; ListCurrentOffset = 0; }

    void CopyData(DualIntrusiveAllocator const &rhs) {
      DataCurrentOffset = rhs.DataCurrentOffset;
      ListCurrentOffset = rhs.ListCurrentOffset;
      memcpy(reinterpret_cast<void*>(Data), reinterpret_cast<void*>(rhs.Data), DataCurrentOffset);
      memcpy(reinterpret_cast<void*>(List), reinterpret_cast<void*>(rhs.List), ListCurrentOffset);
    }

  private:
    uintptr_t Data;
    uintptr_t List;
    size_t DataCurrentOffset {0};
    size_t ListCurrentOffset {0};
    size_t MemorySize;
};


class IRListView final {
  enum Flags : uint64_t {
    FLAG_IsCopy = 1,
    FLAG_Shared = 2,
  };

public:
  IRListView() = delete;
  IRListView(IRListView &&) = delete;

  IRListView(DualIntrusiveAllocator *Data, bool _IsCopy) {
    SetCopy(_IsCopy);
    DataSize = Data->DataSize();
    ListSize = Data->ListSize();

    if (_IsCopy) {
      IRDataInternal = malloc(DataSize + ListSize);
      ListDataInternal = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(IRDataInternal) + DataSize);
      memcpy(IRDataInternal, reinterpret_cast<void*>(Data->DataBegin()), DataSize);
      memcpy(ListDataInternal, reinterpret_cast<void*>(Data->ListBegin()), ListSize);
    }
    else {
      // We are just pointing to the data
      IRDataInternal = reinterpret_cast<void*>(Data->DataBegin());
      ListDataInternal = reinterpret_cast<void*>(Data->ListBegin());
    }
  }

  IRListView(IRListView *Old, bool _IsCopy) {
    SetCopy(_IsCopy);
    DataSize = Old->DataSize;
    ListSize = Old->ListSize;
    if (_IsCopy) {
      IRDataInternal = malloc(DataSize + ListSize);
      ListDataInternal = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(IRDataInternal) + DataSize);
      memcpy(IRDataInternal, Old->IRDataInternal, DataSize);
      memcpy(ListDataInternal, Old->ListDataInternal, ListSize);
    } else {
      IRDataInternal = Old->IRDataInternal;
      ListDataInternal = Old->ListDataInternal;
    }
  }

  ~IRListView() {
    if (IsCopy()) {
      free (IRDataInternal);
      // ListData is just offset from IRData
    }
  }

  void Serialize(std::ostream& stream) {
    void *nul = nullptr;
    //void *IRDataInternal;
    stream.write((char*)&nul, sizeof(nul));
    //void *ListDataInternal;
    stream.write((char*)&nul, sizeof(nul));
    //size_t DataSize;
    stream.write((char*)&DataSize, sizeof(DataSize));
    //size_t ListSize;
    stream.write((char*)&ListSize, sizeof(ListSize));
    //uint64_t Flags;
    uint64_t WrittenFlags = Flags | FLAG_Shared; //on disk format always has the Shared flag
    stream.write((char*)&WrittenFlags, sizeof(WrittenFlags));
    
    // inline data
    stream.write((char*)GetData(), static_cast<std::streamsize>(DataSize));
    stream.write((char*)GetListData(), static_cast<std::streamsize>(ListSize));
  }

  [[nodiscard]] size_t GetInlineSize() const {
    static_assert(sizeof(*this) == 40);
    return sizeof(*this) + DataSize + ListSize;
  }

  [[nodiscard]] IRListView *CreateCopy() {
    return new IRListView(this, true);
  }

  [[nodiscard]] size_t GetDataSize() const { return DataSize; }
  [[nodiscard]] size_t GetListSize() const { return ListSize; }
  [[nodiscard]] size_t GetSSACount() const { return ListSize / sizeof(OrderedNode); }

  [[nodiscard]] bool IsCopy() const {
    return (Flags & FLAG_IsCopy) != 0;
  }
  void SetCopy(bool Set) {
    if (Set) {
      Flags |= FLAG_IsCopy;
    } else {
      Flags &= ~FLAG_IsCopy;
    }
  }

  [[nodiscard]] bool IsShared() const {
    return (Flags & FLAG_Shared) != 0;
  }
  void SetShared(bool Set) {
    if (Set) {
      Flags |= FLAG_Shared;
    } else {
      Flags &= ~FLAG_Shared;
    }
  }

  [[nodiscard]] NodeID GetID(const OrderedNode *Node) const {
    return Node->Wrapped(GetListData()).ID();
  }

  [[nodiscard]] OrderedNode* GetHeaderNode() const {
    OrderedNodeWrapper Wrapped;
    Wrapped.NodeOffset = sizeof(OrderedNode);
    return Wrapped.GetNode(GetListData());
  }

  [[nodiscard]] IROp_IRHeader *GetHeader() const {
    return GetOp<IROp_IRHeader>(GetHeaderNode());
  }

  template <typename T>
  [[nodiscard]] T *GetOp(OrderedNode *Node) const {
    auto OpHeader = Node->Op(GetData());
    auto Op = OpHeader->template CW<T>();

    // If we are casting to something narrower than just the header, check the opcode.
    if constexpr (!std::is_same<T, IROp_Header>::value) {
      LOGMAN_THROW_A_FMT(Op->OPCODE == Op->Header.Op, "Expected Node to be '{}'. Found '{}' instead", GetName(Op->OPCODE), GetName(Op->Header.Op));
    }

    return Op;
  }

  template <typename T>
  [[nodiscard]] T *GetOp(OrderedNodeWrapper Wrapper) const {
    auto Node = Wrapper.GetNode(GetListData());
    return GetOp<T>(Node);
  }

  [[nodiscard]] OrderedNode* GetNode(OrderedNodeWrapper Wrapper) const {
    return Wrapper.GetNode(GetListData());
  }

private:
  struct BlockRange {
    using iterator = NodeIterator;
    const IRListView *View;

    BlockRange(const IRListView *parent) : View(parent) {};

    [[nodiscard]] iterator begin() const noexcept {
      auto Header = View->GetHeader();
      return iterator(View->GetListData(), View->GetData(), Header->Blocks);
    }

    [[nodiscard]] iterator end() const noexcept {
      return iterator(View->GetListData(), View->GetData());
    }
  };

  struct CodeRange {
    using iterator = NodeIterator;
    const IRListView *View;
    const OrderedNodeWrapper BlockWrapper;

    CodeRange(const IRListView *parent, OrderedNodeWrapper block) : View(parent), BlockWrapper(block) {};

    [[nodiscard]] iterator begin() const noexcept {
      auto Block = View->GetOp<IROp_CodeBlock>(BlockWrapper);
      return iterator(View->GetListData(), View->GetData(), Block->Begin);
    }

    [[nodiscard]] iterator end() const noexcept {
      return iterator(View->GetListData(), View->GetData());
    }
  };

  struct AllCodeRange {
    using iterator = AllNodesIterator; // Diffrent Iterator
    const IRListView *View;

    AllCodeRange(const IRListView *parent) : View(parent) {};

    [[nodiscard]] iterator begin() const noexcept {
      auto Header = View->GetHeader();
      return iterator(View->GetListData(), View->GetData(), Header->Blocks);
    }

    [[nodiscard]] iterator end() const noexcept {
      return iterator(View->GetListData(), View->GetData());
    }
  };

public:
  using iterator = NodeIterator;

  [[nodiscard]] BlockRange GetBlocks() const {
    return BlockRange(this);
  }

  [[nodiscard]] CodeRange GetCode(const OrderedNode *block) const {
    return CodeRange(this, block->Wrapped(GetListData()));
  }

  [[nodiscard]] AllCodeRange GetAllCode() const {
    return AllCodeRange(this);
  }

  [[nodiscard]] iterator begin() const noexcept {
    OrderedNodeWrapper Wrapped;
    Wrapped.NodeOffset = sizeof(OrderedNode);
    return iterator(GetListData(), GetData(), Wrapped);
  }

  /**
   * @brief This is not an iterator that you can reverse iterator through!
   *
   * @return Our iterator sentinel to ensure ending correctly
   */
  [[nodiscard]] iterator end() const noexcept {
    OrderedNodeWrapper Wrapped;
    Wrapped.NodeOffset = 0;
    return iterator(GetListData(), GetData(), Wrapped);
  }

  /**
   * @brief Convert a OrderedNodeWrapper to an interator that we can iterate over
   * @return Iterator for this op
   */
  [[nodiscard]] iterator at(OrderedNodeWrapper Wrapped) const noexcept {
    return iterator(GetListData(), GetData(), Wrapped);
  }

  [[nodiscard]] iterator at(NodeID ID) const noexcept {
    OrderedNodeWrapper Wrapped;
    Wrapped.NodeOffset = ID.Value * sizeof(OrderedNode);
    return iterator(GetListData(), GetData(), Wrapped);
  }

  [[nodiscard]] iterator at(const OrderedNode *Node) const noexcept {
    const auto ListData = GetListData();
    auto Wrapped = Node->Wrapped(ListData);
    return iterator(ListData, GetData(), Wrapped);
  }

  [[nodiscard]] uintptr_t GetData() const {
    return reinterpret_cast<uintptr_t>(IRDataInternal ? IRDataInternal : InlineData);
  }

  [[nodiscard]] uintptr_t GetListData() const {
    return reinterpret_cast<uintptr_t>(ListDataInternal ? ListDataInternal : &InlineData[DataSize]);
  }

private:
  void *IRDataInternal;
  void *ListDataInternal;
  size_t DataSize;
  size_t ListSize;
  uint64_t Flags {0};
  uint8_t InlineData[0];
};

struct IRListViewDeleter {
  void operator()(IRListView* r) {
    if (!r->IsShared()) {
      delete r;
    }
  }
};
}

