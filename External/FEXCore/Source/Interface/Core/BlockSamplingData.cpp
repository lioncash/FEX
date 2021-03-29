#include "Interface/Core/BlockSamplingData.h"
#include <FEXCore/Utils/LogManager.h>
#include <cstring>
#include <fstream>

namespace FEXCore {
  void BlockSamplingData::DumpBlockData() {
    std::fstream Output;
    Output.open("output.csv", std::fstream::out | std::fstream::binary);

    if (!Output.is_open())
      return;

    Output << "Entry, Min, Max, Total, Calls, Average" << std::endl;

    for (const auto& [RIP, Block] : SamplingMap) {
      if (Block->TotalCalls == 0)
        continue;

      Output << "0x" << std::hex << RIP
             << ", " << std::dec << Block->Min
             << ", " << std::dec << Block->Max
             << ", " << std::dec << Block->TotalTime
             << ", " << std::dec << Block->TotalCalls
             << ", " << std::dec << ((double)Block->TotalTime / (double)Block->TotalCalls)
             << std::endl;
    }
    Output.close();
    LogMan::Msg::D("Dumped %zu blocks of sampling data", SamplingMap.size());
  }

  BlockSamplingData::BlockData *BlockSamplingData::GetBlockData(uint64_t RIP) {
    auto it = SamplingMap.find(RIP);
    if (it != SamplingMap.end()) {
      return it->second.get();
    }

    auto NewData = std::make_unique<BlockData>();
    NewData->Min = ~0ULL;

    auto Inserted = SamplingMap.insert_or_assign(RIP, std::move(NewData));
    return Inserted.first->second.get();
  }

  BlockSamplingData::~BlockSamplingData() {
    DumpBlockData();
    SamplingMap.clear();
  }
}
