#pragma once
#include <cstdint>
#include <string>
#include <string_view>
#include <optional>

namespace FEXCore::StrConv {
  [[maybe_unused]] static bool Conv(std::string_view Value, bool *Result) {
    *Result = std::stoi(std::string(Value), nullptr, 0) != 0;
    return true;
  }

  [[maybe_unused]] static bool Conv(std::string_view Value, uint8_t *Result) {
    *Result = static_cast<uint8_t>(std::stoul(std::string(Value), nullptr, 0));
    return true;
  }

  [[maybe_unused]] static bool Conv(std::string_view Value, uint16_t *Result) {
    *Result = static_cast<uint16_t>(std::stoul(std::string(Value), nullptr, 0));
    return true;
  }

  [[maybe_unused]] static bool Conv(std::string_view Value, uint32_t *Result) {
    *Result = std::stoul(std::string(Value), nullptr, 0);
    return true;
  }

  [[maybe_unused]] static bool Conv(std::string_view Value, int32_t *Result) {
    *Result = std::stoi(std::string(Value), nullptr, 0);
    return true;
  }

  [[maybe_unused]] static bool Conv(std::string_view Value, uint64_t *Result) {
    *Result = std::stoull(std::string(Value), nullptr, 0);
    return true;
  }
  [[maybe_unused]] static bool Conv(std::string_view Value, std::string *Result) {
    *Result = Value;
    return true;
  }
  template <typename T,
    typename = std::enable_if<std::is_enum<T>::value, T>>
  [[maybe_unused]] static bool Conv(std::string_view Value, T *Result) {
    *Result = static_cast<T>(std::stoull(std::string(Value), nullptr, 0));
    return true;
  }

}
