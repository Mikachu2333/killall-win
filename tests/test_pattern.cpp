/*
 * test_pattern.cpp — Unit tests for the pure matching/parsing logic in
 * pattern.hpp (toLower, globMatch, parseLong/parseULongLong/parseDouble,
 * Pattern). No test framework: plain assertions, exit code 0 = pass.
 *
 * Build/run via CMake (ctest) or directly:
 *   cl /EHsc /std:c++20 test_pattern.cpp
 */
#include "../pattern.hpp"

#include <cstdio>
#include <cstring>
#include <limits>
#include <string>

static int g_failures = 0;

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond)) {                                                             \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);              \
      ++g_failures;                                                            \
    }                                                                          \
  } while (0)

static void testGlobMatch() {
  CHECK(globMatch("note*", "notepad.exe"));
  CHECK(globMatch("note*", "notes.txt"));
  CHECK(!globMatch("note*", "xnote"));
  CHECK(globMatch("*.exe", "notepad.exe"));
  CHECK(!globMatch("*.exe", "notepad.txt"));
  CHECK(globMatch("?", "a"));
  CHECK(!globMatch("?", "ab"));
  CHECK(globMatch("*", ""));
  CHECK(globMatch("*", "anything"));
  CHECK(globMatch("", ""));
  CHECK(globMatch("abc", "ABC")); // case-insensitive
  CHECK(globMatch("a*c", "abc"));
  CHECK(globMatch("a*c", "ac"));
  CHECK(globMatch("*a*b*", "xxaxbxx"));
  CHECK(globMatch("a*b", "acb")); // * matches "c"
  CHECK(!globMatch("a*b", "a"));
  CHECK(!globMatch("a*b", "abx"));
  CHECK(!globMatch("abc", "abd"));
  CHECK(globMatch("a??", "abc"));
  CHECK(!globMatch("a??", "ab"));
}

static void testPattern() {
  // SUBSTRING (default), case-insensitive
  CHECK(Pattern("note").match("notepad.exe"));
  CHECK(Pattern("Note").match("notepad.exe"));
  CHECK(!Pattern("xyz").match("notepad.exe"));
  CHECK(Pattern("").match("anything")); // empty substring matches everything

  // GLOB
  CHECK(Pattern("note*").match("notepad.exe"));
  CHECK(Pattern("*.exe").match("notepad.exe"));
  CHECK(!Pattern("*.exe").match("notepad.txt"));

  // REGEX (/pattern/), case-insensitive
  CHECK(Pattern("/^note/").match("notepad.exe"));
  CHECK(Pattern("/STEAM/").match("steam.exe"));
  CHECK(!Pattern("/^steam$/").match("steam.exe "));
  CHECK(Pattern("/pad\\.exe$/").match("notepad.exe"));
  CHECK(Pattern("/\\.exe$/").match("notepad.exe"));
  CHECK(!Pattern("/\\.exe$/").match("notepad.txt"));

  // invalid regex marks valid == false
  {
    Pattern bad("/(/");
    CHECK(!bad.valid);
  }
  {
    Pattern good("note");
    CHECK(good.valid);
  }
  {
    Pattern good("note*");
    CHECK(good.valid);
  }
}

static void testParseLong() {
  long v = 0;
  CHECK(parseLong("42", v) && v == 42);
  CHECK(parseLong("-5", v) && v == -5);
  CHECK(parseLong("0", v) && v == 0);
  CHECK(parseLong("+7", v) && v == 7);
  CHECK(!parseLong("", v));
  CHECK(!parseLong("abc", v));
  CHECK(!parseLong("12abc", v));
  CHECK(!parseLong("0x10", v)); // base 10 only, trailing "x10" rejected
  CHECK(parseLong(std::to_string(std::numeric_limits<long>::max()), v) &&
        v == std::numeric_limits<long>::max());
  CHECK(!parseLong(std::to_string(std::numeric_limits<long>::max()) + "0", v));
  CHECK(!parseLong(std::to_string(std::numeric_limits<long>::min()) + "0", v));
}

static void testParseULongLong() {
  unsigned long long v = 0;
  CHECK(parseULongLong("42", v) && v == 42);
  CHECK(parseULongLong("0", v) && v == 0);
  CHECK(!parseULongLong("", v));
  CHECK(!parseULongLong("-1", v));
  CHECK(!parseULongLong("+1", v));
  CHECK(!parseULongLong("abc", v));
  CHECK(
      parseULongLong(
          std::to_string(std::numeric_limits<unsigned long long>::max()), v) &&
      v == std::numeric_limits<unsigned long long>::max());
  CHECK(!parseULongLong(
      std::to_string(std::numeric_limits<unsigned long long>::max()) + "0", v));
}

static void testParseDouble() {
  double v = 0.0;
  CHECK(parseDouble("3.14", v) && v > 3.13 && v < 3.15);
  CHECK(parseDouble("-2.5", v) && v == -2.5);
  CHECK(parseDouble("1e10", v) && v == 1e10);
  CHECK(parseDouble("0", v) && v == 0.0);
  CHECK(!parseDouble("", v));
  CHECK(!parseDouble("abc", v));
  CHECK(!parseDouble("inf", v));
  CHECK(!parseDouble("-inf", v));
  CHECK(!parseDouble("nan", v));
  CHECK(!parseDouble("12x", v));
}

static void testToLower() {
  CHECK(toLower("AbC") == "abc");
  CHECK(toLower("") == "");
  CHECK(toLower("ABC123") == "abc123");
}

int main() {
  testGlobMatch();
  testPattern();
  testParseLong();
  testParseULongLong();
  testParseDouble();
  testToLower();
  if (g_failures == 0)
    std::printf("All pattern tests passed.\n");
  else
    std::printf("%d pattern test(s) failed.\n", g_failures);
  return g_failures == 0 ? 0 : 1;
}
