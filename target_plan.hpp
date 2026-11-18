#pragma once

#include <charconv>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct ProcessIdentity {
  std::uint32_t pid = 0;
  std::uint64_t creationTime = 0;
};

inline constexpr char planOption[] = "--execute-targets";

inline std::wstring encodeTarget(ProcessIdentity target) {
  return std::to_wstring(target.pid) + L":" +
         std::to_wstring(target.creationTime);
}

inline bool decodeTargets(int count, char *const *args,
                          std::vector<ProcessIdentity> &targets) {
  std::set<std::uint32_t> seen;
  std::vector<ProcessIdentity> parsed;
  for (int index = 0; index < count; ++index) {
    std::string_view text(args[index]);
    const auto separator = text.find(':');
    if (separator == text.npos)
      return false;
    const char *middle = text.data() + separator;
    const char *end = text.data() + text.size();
    ProcessIdentity target;
    const auto pid = std::from_chars(text.data(), middle, target.pid);
    const auto time = std::from_chars(middle + 1, end, target.creationTime);
    if (pid.ec != std::errc{} || pid.ptr != middle || time.ec != std::errc{} ||
        time.ptr != end || !target.pid || target.pid == 4 ||
        !target.creationTime || !seen.insert(target.pid).second)
      return false;
    parsed.push_back(target);
  }
  if (parsed.empty())
    return false;
  targets = std::move(parsed);
  return true;
}
