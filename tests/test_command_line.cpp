/* Unit tests for command_line.hpp. */
#include "../command_line.hpp"

#include <cstdio>
#include <string>

static int g_failures = 0;

#define CHECK_EQ(actual, expected)                                             \
  do {                                                                         \
    const std::wstring actualValue = (actual);                                 \
    const std::wstring expectedValue = (expected);                             \
    if (actualValue != expectedValue) {                                        \
      std::printf("FAIL %s:%d\n", __FILE__, __LINE__);                         \
      ++g_failures;                                                            \
    }                                                                          \
  } while (0)

int main() {
  CHECK_EQ(quoteWindowsArg(L"plain"), L"plain");
  CHECK_EQ(quoteWindowsArg(L""), L"\"\"");
  CHECK_EQ(quoteWindowsArg(L"two words"), L"\"two words\"");
  CHECK_EQ(quoteWindowsArg(L"tab\tvalue"), L"\"tab\tvalue\"");
  CHECK_EQ(quoteWindowsArg(L"a\"b"), L"\"a\\\"b\"");
  CHECK_EQ(quoteWindowsArg(L"C:\\path with space\\"),
           L"\"C:\\path with space\\\\\"");
  CHECK_EQ(quoteWindowsArg(L"a\\\"b"), L"\"a\\\\\\\"b\"");
  if (g_failures == 0)
    std::printf("All command-line tests passed.\n");
  return g_failures == 0 ? 0 : 1;
}
