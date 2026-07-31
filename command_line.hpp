/*
 * command_line.hpp — Windows command-line quoting helpers.
 *
 * Implements the escaping rules used by CommandLineToArgvW / the Microsoft
 * CRT so elevated relaunches preserve empty arguments, embedded quotes, and
 * trailing backslashes exactly.
 */
#pragma once

#include <string>
#include <string_view>

inline std::wstring quoteWindowsArg(std::wstring_view arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\"") == std::wstring_view::npos)
    return std::wstring(arg);

  std::wstring result;
  result.push_back(L'"');
  size_t backslashes = 0;
  for (const wchar_t c : arg) {
    if (c == L'\\') {
      ++backslashes;
      continue;
    }
    if (c == L'"') {
      result.append(backslashes * 2 + 1, L'\\');
      result.push_back(L'"');
      backslashes = 0;
      continue;
    }
    result.append(backslashes, L'\\');
    backslashes = 0;
    result.push_back(c);
  }
  // Backslashes immediately before the closing quote must be doubled.
  result.append(backslashes * 2, L'\\');
  result.push_back(L'"');
  return result;
}
