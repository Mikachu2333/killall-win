/*
 * pattern.hpp — Pure matching/parsing logic shared by killall.cpp and its
 * unit tests (tests/test_pattern.cpp).
 *
 * Header-only with no Windows API dependencies so it can be compiled and
 * tested in isolation. Functions that need Win32 (toNarrow/toWide, process
 * queries, etc.) intentionally stay in killall.cpp.
 */
#pragma once

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <regex>
#include <string>

// ─── Utilities ───────────────────────────────────────────────────────────────
inline std::string toLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return (char)::tolower(c); });
  return s;
}

// glob match: * = any sequence, ? = any char (case-insensitive)
inline bool globMatch(const std::string &pat, const std::string &str) {
  std::string p = toLower(pat), s = toLower(str);
  size_t pi = 0, si = 0, star = std::string::npos, match = 0;
  while (si < s.size()) {
    if (pi < p.size() && (p[pi] == s[si] || p[pi] == '?')) {
      pi++;
      si++;
    } else if (pi < p.size() && p[pi] == '*') {
      star = pi++;
      match = si;
    } else if (star != std::string::npos) {
      pi = star + 1;
      si = ++match;
    } else
      return false;
  }
  while (pi < p.size() && p[pi] == '*')
    pi++;
  return pi == p.size();
}

// ─── Safe numeric parsing helpers ────────────────────────────────────────────
inline bool parseLong(const std::string &s, long &out) {
  if (s.empty())
    return false;
  char *end = nullptr;
  errno = 0;
  out = strtol(s.c_str(), &end, 10);
  if (errno == ERANGE || end == s.c_str() || *end != '\0')
    return false;
  return true;
}
inline bool parseULongLong(const std::string &s, unsigned long long &out) {
  if (s.empty() || s.front() == '-' || s.front() == '+')
    return false;
  char *end = nullptr;
  errno = 0;
  out = strtoull(s.c_str(), &end, 10);
  if (errno == ERANGE || end == s.c_str() || *end != '\0')
    return false;
  return true;
}
inline bool parseDouble(const std::string &s, double &out) {
  if (s.empty())
    return false;
  char *end = nullptr;
  errno = 0;
  out = strtod(s.c_str(), &end);
  if (errno == ERANGE || end == s.c_str() || *end != '\0' ||
      !std::isfinite(out))
    return false;
  return true;
}

// ─── Pattern object ──────────────────────────────────────────────────────────
struct Pattern {
  enum Type { SUBSTRING, GLOB, REGEX } type;
  std::string raw;
  std::regex re;
  bool valid = true;

  explicit Pattern(const std::string &pat) : type(SUBSTRING), raw(pat) {
    if (pat.size() >= 2 && pat.front() == '/' && pat.back() == '/') {
      type = REGEX;
      std::string inner = pat.substr(1, pat.size() - 2);
      try {
        re = std::regex(inner, std::regex::icase | std::regex::ECMAScript);
      } catch (const std::regex_error &) {
        valid = false;
      }
    } else if (pat.find('*') != std::string::npos ||
               pat.find('?') != std::string::npos) {
      type = GLOB;
    }
  }

  bool match(const std::string &name) const {
    switch (type) {
    case SUBSTRING:
      return toLower(name).find(toLower(raw)) != std::string::npos;
    case GLOB:
      return globMatch(raw, name);
    case REGEX:
      return std::regex_search(name, re);
    }
    return false;
  }
};
