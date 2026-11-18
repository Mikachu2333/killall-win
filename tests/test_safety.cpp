#define wmain killallEntry
#include "../killall.cpp"
#undef wmain

static int failures = 0;

static void check(bool condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "FAIL: %s\n", message);
    ++failures;
  }
}

static bool decode(std::vector<std::string> arguments,
                   std::vector<ProcessIdentity> &targets) {
  std::vector<char *> pointers;
  for (auto &argument : arguments)
    pointers.push_back(argument.data());
  return decodeTargets(static_cast<int>(pointers.size()), pointers.data(),
                       targets);
}

static void testPlan() {
  std::vector<ProcessIdentity> targets;
  check(decode({toNarrow(encodeTarget({12, 34})),
                "4294967295:18446744073709551615"},
               targets) &&
            targets.size() == 2 && targets[0].pid == 12 &&
            targets[0].creationTime == 34 && targets[1].pid == UINT32_MAX &&
            targets[1].creationTime == UINT64_MAX,
        "identity round trip and order");
  for (const auto &bad :
       {"", "0:1", "4:1", "1:0", "1:-1", "1: 2", "4294967296:1",
        "1:18446744073709551616", "1:2:3", "1:", ":2", "--tree", "*"}) {
    check(!decode({"20:1", bad}, targets) && targets.size() == 2 &&
              targets[0].pid == 12,
          "reject whole malformed plan");
  }
  check(!decode({"20:1", "20:2"}, targets) && !decode({}, targets),
        "duplicate and empty plans");
}

static void testFilters() {
  ProcInfo target;
  target.pid = 77;
  target.creationTime = 33;
  ProcInfo older = target, younger = target;
  older.pid = 78;
  older.ppid = target.pid;
  older.creationTime--;
  younger.pid = 79;
  younger.ppid = target.pid;
  younger.creationTime++;
  check(getProcessTree(target, {target, older, younger}) ==
            std::set<DWORD>{77, 79},
        "tree ignores a reused parent PID");
  Args args;
  args.cmdlinePat = "/^$/";
  bool valid = false;
  g_cmdlineCacheFailed = true;
  check(filterProcs({target}, args, valid).empty() && valid &&
            unreadableProcesses.count(77),
        "unreadable command line cannot match empty text");
  g_cmdlineCache.emplace(target.pid, "");
  check(filterProcs({target}, args, valid).size() == 1 && valid,
        "readable empty command line matches");
}

static BOOL WINAPI queryFailed(HANDLE, PBOOL) { return FALSE; }
static BOOL WINAPI queryCritical(HANDLE, PBOOL value) {
  *value = TRUE;
  return TRUE;
}

static void testOwnedProcess() {
  std::wstring path;
  if (!getExecutablePath(path)) {
    check(false, "resolve test executable");
    return;
  }
  std::wstring command = quoteWindowsArg(path) + L" --test-sleeper";
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION info{};
  if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info)) {
    check(false, "create private test child");
    return;
  }
  auto child = makeHandle(info.hProcess);
  auto thread = makeHandle(info.hThread);
  std::vector<ProcInfo> snapshot;
  check(enumProcesses(snapshot), "read system snapshot");
  const auto entry =
      std::find_if(snapshot.begin(), snapshot.end(), [&](const auto &process) {
        return process.pid == info.dwProcessId;
      });
  const auto created = creationTimeOf(child.get());
  check(entry != snapshot.end() && entry->creationTime == created && created &&
            entry->ppid == GetCurrentProcessId(),
        "snapshot identifies the child and parent");
  check(!criticalOrUnknown(child.get(), nullptr),
        "legacy critical-state query on owned child");
  check(criticalOrUnknown(nullptr, nullptr) &&
            criticalOrUnknown(child.get(), queryFailed) &&
            criticalOrUnknown(child.get(), queryCritical),
        "unknown and critical states refuse termination");
  check(executeTargets({{info.dwProcessId, created + 1}}) == 2 &&
            WaitForSingleObject(child.get(), 0) == WAIT_TIMEOUT,
        "recycled PID survives stale plan");
  if (entry != snapshot.end()) {
    Args preview;
    preview.yes = true;
    preview.dryRun = true;
    check(doKill({*entry}, preview, snapshot) == 0 &&
              WaitForSingleObject(child.get(), 0) == WAIT_TIMEOUT,
          "explicit dry run wins over yes");
    check(executeTargets({*entry}) == 0 && childResult(child.get()) == 1,
          "exact target terminates and child exit code propagates");
  }
  check(childResult(nullptr) == 2, "missing child handle fails");
}

int wmain(int argc, wchar_t **argv) {
  if (argc >= 2 && toNarrow(argv[1]) == planOption) {
    if (argc == 4 && std::wstring_view(argv[2]) == L"111:222" &&
        std::wstring_view(argv[3]) == L"333:444")
      return 37;
    return 1;
  }
  if (argc == 2 && std::wstring_view(argv[1]) == L"--test-sleeper") {
    Sleep(10000);
    return 73;
  }
  testPlan();
  testFilters();
  testOwnedProcess();
  check(launchTargetWorker({{111, 222}, {333, 444}}, L"open") == 37,
        "Shell worker receives only the ordered identities and returns its "
        "exit code");
  return failures ? 1 : 0;
}
