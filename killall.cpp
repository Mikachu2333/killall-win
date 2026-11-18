/*
 * killall.cpp — Windows Process Termination Tool
 * Supports Windows 7 through Windows 11
 */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0601
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <objbase.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <wbemidl.h>
#include <winternl.h>

#include "version.hpp"
#include "command_line.hpp"
#include "pattern.hpp"
#include "target_plan.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <regex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ─── Win32 resource management ──────────────────────────────────────────────
struct HandleCloser {
  void operator()(void *handle) const noexcept {
    if (handle && handle != INVALID_HANDLE_VALUE)
      CloseHandle(static_cast<HANDLE>(handle));
  }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

static UniqueHandle makeHandle(HANDLE handle) {
  return UniqueHandle(handle == INVALID_HANDLE_VALUE ? nullptr : handle);
}

// Process names and messages are UTF-8; switch the console output code page
// for the duration of the run and restore it on exit so redirected logs and
// other programs sharing the console are not left in a modified state.
struct ConsoleUtf8Guard {
  UINT original = 0;
  bool active = false;
  ConsoleUtf8Guard() {
    original = GetConsoleOutputCP();
    active = SetConsoleOutputCP(CP_UTF8) != FALSE;
  }
  ~ConsoleUtf8Guard() {
    if (active)
      SetConsoleOutputCP(original);
  }
};

// ANSI escapes are deliberately disabled. Windows 7 and redirected output do
// not reliably support VT sequences, and raw escapes make logs unreadable.
#define RED(s) s
#define GREEN(s) s
#define YELLOW(s) s
#define CYAN(s) s
#define BOLD(s) s

// ─── Utilities ───────────────────────────────────────────────────────────────
static std::string toNarrow(const std::wstring &w) {
  if (w.empty())
    return {};
  if (w.size() > static_cast<size_t>(INT_MAX))
    return {};
  const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(),
                                    static_cast<int>(w.size()), nullptr, 0,
                                    nullptr, nullptr);
  if (n <= 0)
    return {};
  std::string s(static_cast<size_t>(n), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(),
                          static_cast<int>(w.size()), s.data(), n, nullptr,
                          nullptr) != n)
    return {};
  return s;
}

static std::wstring toWide(const std::string &s) {
  if (s.empty())
    return {};
  if (s.size() > static_cast<size_t>(INT_MAX))
    return {};
  const int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                                    static_cast<int>(s.size()), nullptr, 0);
  if (n <= 0)
    return {};
  std::wstring w(static_cast<size_t>(n), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                          static_cast<int>(s.size()), w.data(), n) != n)
    return {};
  return w;
}

// Matching/parsing logic (toLower, globMatch, parseLong/parseULongLong/
// parseDouble, Pattern) lives in pattern.hpp so it can be unit-tested.

// ─── Process info struct ─────────────────────────────────────────────────────
struct ProcInfo : ProcessIdentity {
  DWORD ppid = 0;
  std::string name;
  SIZE_T workingSetBytes = 0;
  ULONGLONG cpuTime = 0;
  double cpuPercent = 0.0;
};

// ─── Enumerate all processes ─────────────────────────────────────────────────
static ULONGLONG creationTimeOf(HANDLE handle);

static bool enumProcesses(std::vector<ProcInfo> &processes) {
  struct Times {
    BYTE accounting[24];
    LARGE_INTEGER created, user, kernel;
  };
  static_assert(sizeof(Times) == sizeof(SYSTEM_PROCESS_INFORMATION::Reserved1));
  const auto query =
      reinterpret_cast<decltype(&NtQuerySystemInformation)>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
  if (!query)
    return false;
  std::vector<BYTE> buffer(256 * 1024);
  ULONG used = 0;
  for (;;) {
    const NTSTATUS status = query(SystemProcessInformation, buffer.data(),
                                  static_cast<ULONG>(buffer.size()), &used);
    if (status >= 0)
      break;
    if (status != static_cast<NTSTATUS>(0xC0000004L) || used > ULONG_MAX / 2 ||
        buffer.size() > ULONG_MAX / 2)
      return false;
    buffer.resize(std::max<size_t>(used, buffer.size() * 2));
  }
  if (used > buffer.size())
    return false;
  size_t offset = 0;
  bool verifiedLayout = false;
  while (used - offset >= sizeof(SYSTEM_PROCESS_INFORMATION)) {
    const auto *entry = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION *>(
        buffer.data() + offset);
    ProcInfo process;
    process.pid = HandleToULong(entry->UniqueProcessId);
    process.ppid = HandleToULong(entry->Reserved2);
    Times times{};
    std::memcpy(&times, entry->Reserved1, sizeof(times));
    process.creationTime = static_cast<ULONGLONG>(times.created.QuadPart);
    if (process.pid == GetCurrentProcessId())
      verifiedLayout =
          process.creationTime &&
          process.creationTime == creationTimeOf(GetCurrentProcess());
    process.cpuTime =
        static_cast<ULONGLONG>(times.user.QuadPart) + times.kernel.QuadPart;
    process.workingSetBytes = entry->WorkingSetSize;
    const auto &name = entry->ImageName;
    if (name.Length) {
      const auto begin = reinterpret_cast<uintptr_t>(buffer.data());
      const auto address = reinterpret_cast<uintptr_t>(name.Buffer);
      if (address < begin || address - begin > used ||
          name.Length > used - (address - begin) ||
          name.Length % sizeof(wchar_t) != 0)
        return false;
      process.name = toLower(
          toNarrow(std::wstring(name.Buffer, name.Length / sizeof(wchar_t))));
    }
    processes.push_back(std::move(process));
    if (!entry->NextEntryOffset)
      return verifiedLayout;
    if (entry->NextEntryOffset < sizeof(*entry) ||
        entry->NextEntryOffset > used - offset ||
        entry->NextEntryOffset % alignof(SYSTEM_PROCESS_INFORMATION) != 0)
      return false;
    offset += entry->NextEntryOffset;
  }
  return false;
}

static ULONGLONG creationTimeOf(HANDLE handle) {
  FILETIME created{}, exited{}, kernel{}, user{};
  if (!GetProcessTimes(handle, &created, &exited, &kernel, &user))
    return 0;
  return (static_cast<ULONGLONG>(created.dwHighDateTime) << 32) |
         created.dwLowDateTime;
}

static std::wstring processPath(HANDLE handle) {
  std::wstring path(32768, L'\0');
  DWORD size = static_cast<DWORD>(path.size());
  if (!QueryFullProcessImageNameW(handle, 0, path.data(), &size))
    return {};
  path.resize(size);
  return path;
}

// ─── WMI command-line cache ──────────────────────────────────────────────────
template <typename T> struct ComReleaser {
  void operator()(T *value) const noexcept {
    if (value)
      value->Release();
  }
};
template <typename T> using UniqueCom = std::unique_ptr<T, ComReleaser<T>>;
struct BstrDeleter {
  void operator()(wchar_t *value) const noexcept { SysFreeString(value); }
};
using UniqueBstr = std::unique_ptr<wchar_t, BstrDeleter>;

static std::map<DWORD, std::string> g_cmdlineCache;
static bool g_cmdlineCacheBuilt = false;
static bool g_cmdlineCacheFailed = false;
static std::set<DWORD> unreadableProcesses;

static void buildCmdlineCache() {
  if (g_cmdlineCacheBuilt || g_cmdlineCacheFailed)
    return;
  // Any WMI failure marks the cache as failed for the rest of the run:
  // retrying on every getCmdline() call would pay the WMI latency each time,
  // so getCmdline() prints a one-time warning instead.

  IWbemLocator *rawLocator = nullptr;
  if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                              IID_IWbemLocator,
                              reinterpret_cast<void **>(&rawLocator))) ||
      !rawLocator) {
    g_cmdlineCacheFailed = true;
    return;
  }
  UniqueCom<IWbemLocator> locator(rawLocator);

  UniqueBstr nameSpace(SysAllocString(L"ROOT\\CIMV2"));
  if (!nameSpace) {
    g_cmdlineCacheFailed = true;
    return;
  }
  IWbemServices *rawServices = nullptr;
  HRESULT hr =
      locator->ConnectServer(nameSpace.get(), nullptr, nullptr, nullptr, 0,
                             nullptr, nullptr, &rawServices);
  if (FAILED(hr) || !rawServices) {
    g_cmdlineCacheFailed = true;
    return;
  }
  UniqueCom<IWbemServices> services(rawServices);

  hr = CoSetProxyBlanket(services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                         nullptr, RPC_C_AUTHN_LEVEL_CALL,
                         RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
  if (FAILED(hr)) {
    g_cmdlineCacheFailed = true;
    return;
  }

  UniqueBstr wql(SysAllocString(L"WQL"));
  UniqueBstr query(
      SysAllocString(L"SELECT ProcessId, CommandLine FROM Win32_Process"));
  if (!wql || !query) {
    g_cmdlineCacheFailed = true;
    return;
  }
  IEnumWbemClassObject *rawEnumerator = nullptr;
  hr =
      services->ExecQuery(wql.get(), query.get(),
                          WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                          nullptr, &rawEnumerator);
  if (FAILED(hr) || !rawEnumerator) {
    g_cmdlineCacheFailed = true;
    return;
  }
  UniqueCom<IEnumWbemClassObject> enumerator(rawEnumerator);

  for (;;) {
    IWbemClassObject *rawObject = nullptr;
    ULONG returned = 0;
    hr = enumerator->Next(5000, 1, &rawObject, &returned);
    UniqueCom<IWbemClassObject> object(rawObject);
    if (FAILED(hr) || hr == WBEM_S_TIMEDOUT) {
      g_cmdlineCacheFailed = true;
      break;
    }
    if (!returned || !object)
      break;

    VARIANT pidValue{};
    VARIANT commandValue{};
    VariantInit(&pidValue);
    VariantInit(&commandValue);
    const HRESULT pidHr =
        object->Get(L"ProcessId", 0, &pidValue, nullptr, nullptr);
    const HRESULT commandHr =
        object->Get(L"CommandLine", 0, &commandValue, nullptr, nullptr);
    const bool validPid =
        SUCCEEDED(pidHr) && (pidValue.vt == VT_I4 || pidValue.vt == VT_UI4);
    if (validPid && SUCCEEDED(commandHr) && commandValue.vt == VT_BSTR &&
        commandValue.bstrVal) {
      const DWORD pid = pidValue.vt == VT_UI4
                            ? pidValue.ulVal
                            : static_cast<DWORD>(pidValue.lVal);
      const std::wstring wide(commandValue.bstrVal,
                              SysStringLen(commandValue.bstrVal));
      auto text = toNarrow(wide);
      if (!text.empty() || wide.empty())
        g_cmdlineCache.emplace(pid, std::move(text));
    }
    VariantClear(&pidValue);
    VariantClear(&commandValue);
  }
  g_cmdlineCacheBuilt = true;
}

static const std::string *getCmdline(DWORD pid) {
  buildCmdlineCache();
  if (g_cmdlineCacheFailed) {
    static bool warned = false;
    if (!warned) {
      warned = true;
      fprintf(stderr, RED("  Warning:") " WMI command-line query incomplete\n");
    }
  }
  auto it = g_cmdlineCache.find(pid);
  if (it != g_cmdlineCache.end())
    return &it->second;
  unreadableProcesses.insert(pid);
  return nullptr;
}

// ─── Loaded modules ──────────────────────────────────────────────────────────
// Iterates loaded modules of pid; returns true as soon as fn returns true.
template <typename Fn> static bool forEachModule(DWORD pid, Fn &&fn) {
  auto snap = makeHandle(
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
  if (!snap) {
    if (GetLastError() != ERROR_INVALID_PARAMETER)
      unreadableProcesses.insert(pid);
    return false;
  }
  MODULEENTRY32W me{};
  me.dwSize = sizeof(me);
  bool found = false;
  if (Module32FirstW(static_cast<HANDLE>(snap.get()), &me)) {
    do {
      if (fn(me)) {
        found = true;
        break;
      }
    } while (Module32NextW(static_cast<HANDLE>(snap.get()), &me));
  }
  if (!found && GetLastError() != ERROR_NO_MORE_FILES)
    unreadableProcesses.insert(pid);
  return found;
}

// The caller builds the Pattern once so /regex/ patterns are compiled once
// for the whole scan instead of once per process.
static bool processHasModule(DWORD pid, const Pattern &pat) {
  return forEachModule(pid, [&pat](const MODULEENTRY32W &me) {
    const std::string name = toLower(toNarrow(me.szModule));
    const std::string path = toLower(toNarrow(me.szExePath));
    return pat.match(name) || pat.match(path);
  });
}

// ─── Network / ports ─────────────────────────────────────────────────────────
// Local TCP/UDP tables (IPv4 + IPv6) are snapshotted once per run. Checking
// each process against freshly queried tables would re-enumerate the whole
// table set 4x per PID, which makes `networkapps` and `--port` scans slow.
struct NetworkTables {
  std::vector<BYTE> tcp4, tcp6, udp4, udp6;
};
static const NetworkTables &networkTables() {
  static const NetworkTables tables = [] {
    NetworkTables t;
    // The first call with a null buffer returns ERROR_INSUFFICIENT_BUFFER and
    // only fills sz; only the second call returns NO_ERROR on success.
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL,
                        0);
    if (sz > 0) {
      t.tcp4.resize(sz);
      if (GetExtendedTcpTable(t.tcp4.data(), &sz, FALSE, AF_INET,
                              TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        t.tcp4.clear();
    }
    sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL,
                        0);
    if (sz > 0) {
      t.tcp6.resize(sz);
      if (GetExtendedTcpTable(t.tcp6.data(), &sz, FALSE, AF_INET6,
                              TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
        t.tcp6.clear();
    }
    sz = 0;
    GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (sz > 0) {
      t.udp4.resize(sz);
      if (GetExtendedUdpTable(t.udp4.data(), &sz, FALSE, AF_INET,
                              UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
        t.udp4.clear();
    }
    sz = 0;
    GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (sz > 0) {
      t.udp6.resize(sz);
      if (GetExtendedUdpTable(t.udp6.data(), &sz, FALSE, AF_INET6,
                              UDP_TABLE_OWNER_PID, 0) != NO_ERROR)
        t.udp6.clear();
    }
    return t;
  }();
  return tables;
}

// All four MIB_*TABLE_OWNER_PID structs share the layout dwNumEntries followed
// by an inline row array; the row fields used here are identical in type.
template <typename Table>
static bool tableHasPort(const std::vector<BYTE> &buf, DWORD pid, int portLo,
                         int portHi) {
  if (buf.size() < sizeof(Table))
    return false;
  const auto *table = reinterpret_cast<const Table *>(buf.data());
  // sizeof(Table) includes one inline row, so clamp the iteration to the rows
  // the snapshot can actually hold; a malformed dwNumEntries must never walk
  // past the buffer.
  const size_t capacityRows =
      (buf.size() - sizeof(Table)) / sizeof(table->table[0]) + 1;
  const DWORD count =
      std::min<DWORD>(table->dwNumEntries, static_cast<DWORD>(capacityRows));
  for (DWORD i = 0; i < count; ++i) {
    const auto &row = table->table[i];
    if (row.dwOwningPid == pid) {
      const int lp =
          static_cast<int>(ntohs(static_cast<u_short>(row.dwLocalPort)));
      if (lp >= portLo && lp <= portHi)
        return true;
    }
  }
  return false;
}

static bool processHasPort(DWORD pid, int portLo, int portHi) {
  const NetworkTables &t = networkTables();
  return tableHasPort<MIB_TCPTABLE_OWNER_PID>(t.tcp4, pid, portLo, portHi) ||
         tableHasPort<MIB_TCP6TABLE_OWNER_PID>(t.tcp6, pid, portLo, portHi) ||
         tableHasPort<MIB_UDPTABLE_OWNER_PID>(t.udp4, pid, portLo, portHi) ||
         tableHasPort<MIB_UDP6TABLE_OWNER_PID>(t.udp6, pid, portLo, portHi);
}
static bool processHasAnyNetwork(DWORD pid) {
  return processHasPort(pid, 1, 65535);
}

// ─── Window title ────────────────────────────────────────────────────────────
// The Pattern is precompiled by the caller and passed by pointer through the
// LPARAM: EnumWindows callbacks fire once per top-level window, so building
// the Pattern inside the callback would recompile /regex/ patterns per window.
struct WinEnumCtx {
  DWORD pid;
  const Pattern *pat;
  bool found;
};
static BOOL CALLBACK enumWinProc(HWND hwnd, LPARAM lp) {
  if (lp == 0)
    return FALSE;
  auto *ctx = reinterpret_cast<WinEnumCtx *>(lp);
  DWORD wpid = 0;
  GetWindowThreadProcessId(hwnd, &wpid);
  if (wpid == ctx->pid) {
    // EnumWindows yields top-level windows only. For cross-process top-level
    // windows GetWindowTextW reads the system's caption cache directly -- it
    // does not post WM_GETTEXT -- so it cannot block on a hung window, unlike
    // SendMessageTimeout(WM_GETTEXT) which would time out before matching.
    wchar_t title[512] = {};
    if (GetWindowTextW(hwnd, title, 512) > 0) {
      if (ctx->pat->match(toNarrow(title))) {
        ctx->found = true;
        return FALSE;
      }
    }
  }
  return TRUE;
}
static bool processHasWindow(DWORD pid, const Pattern &pat) {
  WinEnumCtx ctx = {pid, &pat, false};
  EnumWindows(enumWinProc, reinterpret_cast<LPARAM>(&ctx));
  return ctx.found;
}

// ─── Hung detection ──────────────────────────────────────────────────────────
struct HungCtx {
  DWORD pid;
  bool hung;
};
static BOOL CALLBACK enumHungProc(HWND hwnd, LPARAM lp) {
  if (lp == 0)
    return FALSE;
  auto *ctx = reinterpret_cast<HungCtx *>(lp);
  DWORD wpid = 0;
  GetWindowThreadProcessId(hwnd, &wpid);
  if (wpid == ctx->pid && IsWindow(hwnd)) {
    DWORD_PTR result = 0;
    // A responsive window answers WM_NULL quickly with a non-zero return.
    // A zero return means the window did not respond within the timeout.
    // GetLastError is NOT a reliable hung indicator here: when
    // SMTO_ABORTIFHUNG bails out early on a hung thread it returns 0 while
    // leaving GetLastError at ERROR_SUCCESS on current Windows versions.
    SetLastError(ERROR_SUCCESS);
    if (SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK,
                            2000, &result) == 0) {
      const auto error = GetLastError();
      if (error != ERROR_SUCCESS && error != ERROR_TIMEOUT) {
        if (error == ERROR_ACCESS_DENIED)
          unreadableProcesses.insert(wpid);
        return TRUE;
      }
      ctx->hung = true;
      return FALSE;
    }
  }
  return TRUE;
}
static bool isProcessHung(DWORD pid) {
  HungCtx ctx = {pid, false};
  EnumWindows(enumHungProc, reinterpret_cast<LPARAM>(&ctx));
  return ctx.hung;
}

// ─── CPU usage (two-snapshot) ────────────────────────────────────────────────
static std::optional<std::map<DWORD, double>>
measureCpuUsage(int sampleSecs, const std::vector<ProcInfo> &allProcs) {
  std::map<DWORD, const ProcInfo *> first;
  for (const auto &process : allProcs)
    first.emplace(process.pid, &process);
  ULONGLONG wallStart = 0;
  if (!QueryUnbiasedInterruptTime(&wallStart))
    return std::nullopt;
  printf(YELLOW("  Sampling CPU for %d second(s)...\n"), sampleSecs);
  Sleep(static_cast<DWORD>(sampleSecs) * 1000U);
  ULONGLONG wallEnd = 0;
  std::vector<ProcInfo> second;
  if (!enumProcesses(second) || !QueryUnbiasedInterruptTime(&wallEnd) ||
      wallEnd <= wallStart)
    return std::nullopt;
  const ULONGLONG wallDiff = wallEnd - wallStart;

  std::map<DWORD, double> result;
  for (const auto &process : second) {
    const auto previous = first.find(process.pid);
    if (previous == first.end() || !process.creationTime ||
        process.creationTime != previous->second->creationTime ||
        process.cpuTime < previous->second->cpuTime)
      continue;
    result[process.pid] =
        static_cast<double>(process.cpuTime - previous->second->cpuTime) /
        static_cast<double>(wallDiff) * 100.0;
  }
  return result;
}

// ─── GPU detection (module-based) ────────────────────────────────────────────
static bool processUsesGPU(DWORD pid) {
  static const char *gpuMods[] = {
      "d3d11.dll",    "d3d12.dll",    "d3d9.dll",     "dxgi.dll",
      "nvoglv64.dll", "nvoglv32.dll", "ig4icd64.dll", "atig6pxx.dll",
      "vulkan-1.dll", "opengl32.dll", "nvcuda.dll",   "nvml.dll",
      "atioglxx.dll", "atigktxx.dll", nullptr};
  return forEachModule(pid, [](const MODULEENTRY32W &me) {
    const std::string name = toLower(toNarrow(me.szModule));
    for (int i = 0; gpuMods[i]; ++i)
      if (name == gpuMods[i])
        return true;
    return false;
  });
}

// ─── LLM detection ───────────────────────────────────────────────────────────
static const char *LLM_KEYWORDS[] = {
    "ollama",    "llama",   "koboldcpp",  "textgen",     "lmstudio",
    "lm studio", "jan",     "gpt4all",    "oobabooga",   "open-webui",
    "localai",   "vllm",    "xinference", "fastchat",    "exllama",
    "rwkv",      "whisper", "lm_studio",  "anythingllm", "msty",
    "llamaedge", "cortex",  nullptr};
static const char *AI_CMDLINE_KEYWORDS[] = {".gguf",
                                            ".ggml",
                                            ".safetensors",
                                            ".ckpt",
                                            "fooocus",
                                            "stable-diffusion",
                                            "stable_diffusion",
                                            "webui.py",
                                            "launch.py",
                                            "comfyui",
                                            "comfy_ui",
                                            "invokeai",
                                            "automatic1111",
                                            "sdnext",
                                            "vladmandic",
                                            "kohya",
                                            "sd-scripts",
                                            "novelai",
                                            "naifu",
                                            "deforum",
                                            "diffusers",
                                            "txt2img",
                                            "img2img",
                                            "server.py",
                                            "llama_cpp",
                                            "llama-cpp",
                                            "entry_with_update.py",
                                            nullptr};

static bool isLLMProcess(const ProcInfo &p) {
  const std::string n = stripExeSuffix(toLower(p.name));
  for (int i = 0; LLM_KEYWORDS[i]; i++)
    if (n.find(LLM_KEYWORDS[i]) != std::string::npos)
      return true;
  const auto *command = getCmdline(p.pid);
  if (!command)
    return false;
  const std::string cmd = toLower(*command);
  for (int i = 0; AI_CMDLINE_KEYWORDS[i]; i++)
    if (cmd.find(AI_CMDLINE_KEYWORDS[i]) != std::string::npos)
      return true;
  return false;
}

// ─── Game detection ──────────────────────────────────────────────────────────
static const char *GAME_MODS[] = {
    "steam_api.dll",   "steam_api64.dll", "unityplayer.dll",
    "physxloader.dll", "bink2w64.dll",    "easyanticheat.dll",
    "nvngx_dlss.dll",  "battleye.dll",    nullptr};
static const char *GAME_NAMES[] = {"steam",
                                   "yuanshen",
                                   "genshin impact",
                                   "genshin impact cloud game",
                                   "starrail",
                                   "epicgameslauncher",
                                   "upc",
                                   "galaxyclient",
                                   "blizzard",
                                   "eadesktop",
                                   "riotclientservices",
                                   "playnite",
                                   "parsec",
                                   "xboxpcapp",
                                   "xboxgamebar",
                                   "xboxpctray",
                                   "xboxappft",
                                   "gamingservices",
                                   "gamingservicesnet",
                                   "xgpuenergy",
                                   "gamingtcui",
                                   "gamedvr",
                                   "minecraft",
                                   "minecraftlauncher",
                                   "minecraftdungeons",
                                   "javaw",
                                   "mcplaceholderstub",
                                   nullptr};

static bool isGameProcess(const ProcInfo &p) {
  const std::string n = stripExeSuffix(toLower(p.name));
  for (int i = 0; GAME_NAMES[i]; i++)
    if (n.find(GAME_NAMES[i]) != std::string::npos)
      return true;
  return forEachModule(p.pid, [](const MODULEENTRY32W &me) {
    const std::string name = toLower(toNarrow(me.szModule));
    for (int i = 0; GAME_MODS[i]; ++i)
      if (name == GAME_MODS[i])
        return true;
    return false;
  });
}

// ─── Process tree ────────────────────────────────────────────────────────────
static std::set<DWORD> getProcessTree(const ProcInfo &root,
                                      const std::vector<ProcInfo> &all) {
  std::set<DWORD> tree;
  std::vector<const ProcInfo *> queue = {&root};
  while (!queue.empty()) {
    const auto &parent = *queue.back();
    queue.pop_back();
    if (!tree.insert(parent.pid).second)
      continue;
    for (auto &p : all)
      if (p.ppid == parent.pid && p.pid != parent.pid && parent.creationTime &&
          p.creationTime >= parent.creationTime)
        queue.push_back(&p);
  }
  return tree;
}

// ─── Elevation (UAC) ─────────────────────────────────────────────────────────
static const std::set<std::string> &protectedNames() {
  static const std::set<std::string> names = {
      "csrss.exe", "lsass.exe",     "services.exe",
      "smss.exe",  "wininit.exe",   "winlogon.exe",
      "registry",  "secure system", "memory compression"};
  return names;
}

static bool isElevated() {
  HANDLE rawToken = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken))
    return false;
  auto token = makeHandle(rawToken);
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  return GetTokenInformation(static_cast<HANDLE>(token.get()), TokenElevation,
                             &elevation, sizeof(elevation), &size) != FALSE &&
         elevation.TokenIsElevated != 0;
}

using CriticalQuery = BOOL(WINAPI *)(HANDLE, PBOOL);

static CriticalQuery criticalQuery() {
  static const auto query = reinterpret_cast<CriticalQuery>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsProcessCritical"));
  return query;
}

static UniqueHandle openForTermination(DWORD pid) {
  const DWORD queryAccess = criticalQuery() ? PROCESS_QUERY_LIMITED_INFORMATION
                                            : PROCESS_QUERY_INFORMATION;
  return makeHandle(
      OpenProcess(PROCESS_TERMINATE | queryAccess | SYNCHRONIZE, FALSE, pid));
}

// True when at least one target cannot even be opened for termination with
// the current token (ERROR_ACCESS_DENIED). Already-exited PIDs
// (ERROR_INVALID_PARAMETER) are not counted; protected processes are skipped
// because elevation would not make them killable anyway.
static bool needsElevation(const std::vector<ProcInfo> &procs) {
  for (const auto &p : procs) {
    if (protectedNames().count(p.name) != 0)
      continue;
    auto handle = openForTermination(p.pid);
    if (!handle && GetLastError() == ERROR_ACCESS_DENIED)
      return true;
  }
  return false;
}

// Only prompt when stdin is an interactive console; scripted or redirected
// input must never trigger a UAC dialog unexpectedly.
static bool confirmElevation() {
  HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  if (!GetConsoleMode(in, &mode))
    return false;
  printf(BOLD(
      "  Some targets require administrator privileges. ") "Elevate and retry? "
                                                           "[y/N] ");
  fflush(stdout);
  const int c = getchar();
  if (c != EOF && c != '\n') {
    int rest = 0;
    do {
      rest = getchar();
    } while (rest != '\n' && rest != EOF);
  }
  return c == 'y' || c == 'Y';
}

static bool getExecutablePath(std::wstring &path) {
  DWORD capacity = MAX_PATH;
  for (;;) {
    std::vector<wchar_t> buffer(capacity);
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), capacity);
    if (length == 0)
      return false;
    if (length < capacity) {
      path.assign(buffer.data(), length);
      return true;
    }
    if (capacity >= 32768)
      return false;
    capacity = capacity > 16384 ? 32768 : capacity * 2;
  }
}

static int childResult(HANDLE child) {
  DWORD status = 0;
  if (!child || WaitForSingleObject(child, INFINITE) != WAIT_OBJECT_0 ||
      !GetExitCodeProcess(child, &status)) {
    fprintf(stderr, "  Cannot obtain the elevated process result\n");
    return 2;
  }
  return static_cast<int>(status);
}

static int launchTargetWorker(const std::vector<ProcessIdentity> &targets,
                              const wchar_t *verb) {
  std::wstring exePath;
  if (!getExecutablePath(exePath)) {
    fprintf(stderr, "  Cannot resolve the executable for elevation\n");
    return 2;
  }
  std::wstring parameters = toWide(planOption);
  for (const auto &target : targets) {
    parameters += L' ';
    parameters += encodeTarget(target);
  }
  if (quoteWindowsArg(exePath).size() + parameters.size() + 2 > 32767) {
    fprintf(stderr, "  Target list exceeds the Windows command-line limit\n");
    return 2;
  }
  SHELLEXECUTEINFOW launch{};
  launch.cbSize = sizeof(launch);
  launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
  launch.lpVerb = verb;
  launch.lpFile = exePath.c_str();
  launch.lpParameters = parameters.c_str();
  launch.nShow = SW_SHOWNORMAL;
  if (!ShellExecuteExW(&launch)) {
    fprintf(stderr, "  Elevation cancelled or failed (Windows error %lu)\n",
            GetLastError());
    return 2;
  }
  auto child = makeHandle(launch.hProcess);
  return childResult(child.get());
}

// ─── Kill a PID ──────────────────────────────────────────────────────────────
static bool criticalOrUnknown(HANDLE handle, CriticalQuery isProcessCritical) {
  BOOL critical = FALSE;
  if (isProcessCritical)
    return !isProcessCritical(handle, &critical) || critical;
  const auto query =
      reinterpret_cast<decltype(&NtQueryInformationProcess)>(GetProcAddress(
          GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
  ULONG breakOnTermination = 0, returned = 0;
  return !query ||
         query(handle, ProcessBreakOnTermination, &breakOnTermination,
               sizeof(breakOnTermination), &returned) < 0 ||
         returned != sizeof(breakOnTermination) || breakOnTermination != 0;
}

static bool isProtectedProcess(HANDLE handle) {
  const auto path = processPath(handle);
  const auto name =
      toLower(toNarrow(path.substr(path.find_last_of(L"\\/") + 1)));
  return name.empty() || protectedNames().count(name) ||
         criticalOrUnknown(handle, criticalQuery());
}

static bool killProcess(ProcessIdentity process) {
  if (process.pid == 0 || process.pid == 4 ||
      process.pid == GetCurrentProcessId() || !process.creationTime)
    return false;
  auto handle = openForTermination(process.pid);
  if (!handle) {
    fprintf(stderr, "  Cannot open PID %lu (Windows error %lu)\n",
            static_cast<unsigned long>(process.pid),
            static_cast<unsigned long>(GetLastError()));
    return false;
  }

  if (creationTimeOf(handle.get()) != process.creationTime) {
    fprintf(stderr,
            "  Refusing PID %lu: cannot verify original process identity\n",
            static_cast<unsigned long>(process.pid));
    return false;
  }
  if (isProtectedProcess(handle.get())) {
    fprintf(stderr,
            "  Refusing PID %lu: protected or critical status unknown\n",
            static_cast<unsigned long>(process.pid));
    return false;
  }
  if (!TerminateProcess(static_cast<HANDLE>(handle.get()), 1)) {
    fprintf(stderr,
            "  TerminateProcess failed for PID %lu (Windows error %lu)\n",
            static_cast<unsigned long>(process.pid),
            static_cast<unsigned long>(GetLastError()));
    return false;
  }
  if (WaitForSingleObject(static_cast<HANDLE>(handle.get()), 5000) !=
      WAIT_OBJECT_0) {
    fprintf(stderr, "  Timed out waiting for PID %lu to terminate\n",
            static_cast<unsigned long>(process.pid));
    return false;
  }
  return true;
}

static int executeTargets(const std::vector<ProcessIdentity> &targets) {
  size_t killed = 0;
  for (const auto &target : targets) {
    if (killProcess(target)) {
      printf("  Killed PID %lu\n", static_cast<unsigned long>(target.pid));
      ++killed;
    }
  }
  printf("  Done: %zu killed, %zu failed.\n", killed, targets.size() - killed);
  return killed == targets.size() ? 0 : 2;
}

// ─── Resolve parent name/pid ─────────────────────────────────────────────────
static DWORD resolveParentPid(const std::string &spec,
                              const std::vector<ProcInfo> &all) {
  unsigned long long numeric = 0;
  if (parseULongLong(spec, numeric)) {
    if (numeric == 0 || numeric > std::numeric_limits<DWORD>::max())
      return 0;
    const DWORD pid = static_cast<DWORD>(numeric);
    return std::any_of(
               all.begin(), all.end(),
               [pid](const ProcInfo &process) { return process.pid == pid; })
               ? pid
               : 0;
  }
  const std::string lower = stripExeSuffix(toLower(spec));
  DWORD result = 0;
  for (const auto &process : all) {
    if (stripExeSuffix(process.name) == lower) {
      if (result != 0)
        return 0; // Ambiguous names are unsafe.
      result = process.pid;
    }
  }
  return result;
}

// ─── Args struct ─────────────────────────────────────────────────────────────
struct Args {
  std::string pattern;
  // Positional arguments that are entirely numeric; treated as PIDs to kill
  // exactly (mutually exclusive with pattern).
  std::vector<unsigned long long> pids;
  std::string subcommand;
  std::string subArg;
  std::string error;
  bool killTree = false;
  bool yes = false;    // -y/--yes: execute the kill
  bool force = false;  // -f/--force: alias of -y (backwards compatibility)
  bool dryRun = false; // -n/--dry-run: explicit dry run (default anyway)
  bool help = false;
  bool version = false;
  std::string cmdlinePat;
  std::string modulePat;
  std::string portSpec;
  std::string windowPat;
  std::string parentSpec;
  int top = 0;
  int sampleSecs = 2;
};

void printVersion() {
  printf("killall v" KILLALL_VERSION_STR " — " KILLALL_DESCRIPTION "\n");
  printf("Copyright: " KILLALL_COPYRIGHT "\n");
}

static void printHelp() {
  puts(BOLD("killall") " \xe2\x80\x94 Windows Process Termination Tool");
  puts("");
  puts(BOLD("USAGE"));
  puts("  killall <pattern> [options]");
  puts("  killall <pid> [<pid> ...] [options]");
  puts("  killall <subcommand> [options]");
  puts("  (Default: dry-run; add -y to actually kill)");
  puts("  (Prompts to elevate when targets need administrator rights)");
  puts("");
  puts(BOLD("PATTERN MATCHING"));
  puts("  name        Exact/substring match (case-insensitive)");
  puts("  part        Substring match");
  puts("  note*       Glob wildcard");
  puts("  /regex/     Regex match");
  puts("  1234        All-numeric arguments are matched as PIDs exactly");
  puts("");
  puts(BOLD("OPTIONS"));
  puts("  -t, --tree               Kill process tree");
  puts("  -y, --yes                Execute the kill (default is dry-run)");
  puts("  -f, --force              Alias of --yes (kept for compatibility)");
  puts("  -n, --dry-run            Explicit dry run (default behavior)");
  puts("  -c, --cmdline <pat>      Match command-line substring or /regex/");
  puts("  -m, --module <dll>       Match loaded module/DLL");
  puts("  -p, --port <N|A-B>       Match TCP/UDP port or range");
  puts("  -w, --window <title>     Match window title substring or /regex/");
  puts("  -P, --parent <pid|name>  Match children of a parent process");
  puts("  -N, --top <N>            Limit ramhog/cpuhog to top N offenders");
  puts("  -s, --sample <N>         CPU sampling interval (seconds)");
  puts("  -h, --help               Show help");
  puts("  Use --window=-text (or --cmdline=-text) for values starting with "
       "'-'.");
  puts("  Process filters apply to pattern/PID mode only.");
  puts("");
  puts(BOLD("SUBCOMMANDS"));
  puts("  hung          Kill hung/frozen apps");
  puts("  networkapps   Kill processes with network connections");
  puts("  ramhog <MB>   Kill processes using >N MB RAM");
  puts("  cpuhog <percent> Kill processes using >N%% CPU");
  puts("  gpu           Kill GPU-using processes");
  puts("  llm           Kill local AI/LLM processes");
  puts("  game          Kill game processes and launchers");
  puts("  restart <name>  Kill and restart a process");
  puts("");
  puts(BOLD("EXAMPLES"));
  puts("  killall notepad");
  puts("  killall 4321 -y");
  puts("  killall 4321 8765 -y");
  puts("  killall chrome -t");
  puts("  killall -p 8080");
  puts("  killall -c /server/");
  puts("  killall hung");
  puts("  killall ramhog 2048");
  puts("  killall cpuhog 90 -N 3");
}

// ─── Parse CLI args ──────────────────────────────────────────────────────────
static const char *SUBCMDS[] = {"hung",   "networkapps", "ramhog",
                                "cpuhog", "gpu",         "llm",
                                "game",   "restart",     nullptr};
static bool isSubcmd(const std::string &s) {
  for (int i = 0; SUBCMDS[i]; i++)
    if (s == SUBCMDS[i])
      return true;
  return false;
}

static Args parseArgs(int argc, char **argv) {
  Args a;
  std::vector<std::string> pos;
  bool sampleSpecified = false;
  std::optional<std::string> attached;
  auto requireValue = [&](int &index, const std::string &option,
                          std::string &destination) {
    if (attached && !attached->empty()) {
      destination = *attached;
      return true;
    }
    if (attached || index + 1 >= argc || argv[index + 1][0] == '\0' ||
        argv[index + 1][0] == '-') {
      a.error = "option '" + option + "' requires a value";
      return false;
    }
    destination = argv[++index];
    return true;
  };

  for (int i = 1; i < argc && a.error.empty(); ++i) {
    std::string arg = argv[i];
    attached.reset();
    const auto equals = arg.find('=');
    if (arg.starts_with('-') && equals != std::string::npos) {
      attached = arg.substr(equals + 1);
      arg.resize(equals);
      static const std::set<std::string> valued = {
          "-w", "--window", "-c", "--cmdline", "-p", "--port", "-m", "--module",
          "-P", "--parent", "-s", "--sample",  "-N", "--top"};
      if (!valued.count(arg)) {
        a.error = "unexpected option '" + std::string(argv[i]) + "'";
        break;
      }
    }
    if (arg == "--") {
      while (++i < argc)
        pos.emplace_back(argv[i]);
      break;
    } else if (arg == "-h" || arg == "--help")
      a.help = true;
    else if (arg == "-V" || arg == "--version")
      a.version = true;
    else if (arg == "-t" || arg == "--tree")
      a.killTree = true;
    else if (arg == "-y" || arg == "--yes")
      a.yes = true;
    else if (arg == "-f" || arg == "--force")
      a.force = true;
    else if (arg == "-n" || arg == "--dry-run")
      a.dryRun = true;
    else if (arg == "-c" || arg == "--cmdline")
      requireValue(i, arg, a.cmdlinePat);
    else if (arg == "-m" || arg == "--module")
      requireValue(i, arg, a.modulePat);
    else if (arg == "-p" || arg == "--port")
      requireValue(i, arg, a.portSpec);
    else if (arg == "-w" || arg == "--window")
      requireValue(i, arg, a.windowPat);
    else if (arg == "-P" || arg == "--parent")
      requireValue(i, arg, a.parentSpec);
    else if (arg == "-N" || arg == "--top" || arg == "-s" ||
             arg == "--sample") {
      std::string value;
      if (!requireValue(i, arg, value))
        continue;
      long parsed = 0;
      const long maximum = (arg == "-s" || arg == "--sample") ? 3600 : INT_MAX;
      if (!parseLong(value, parsed) || parsed <= 0 || parsed > maximum) {
        a.error = "invalid value '" + value + "' for option '" + arg + "'";
        continue;
      }
      if (arg == "-s" || arg == "--sample") {
        sampleSpecified = true;
        a.sampleSecs = static_cast<int>(parsed);
      } else
        a.top = static_cast<int>(parsed);
    } else if (!arg.empty() && arg.front() == '-') {
      a.error = "unknown option '" + arg + "'";
    } else {
      pos.push_back(arg);
    }
  }

  if (!a.error.empty())
    return a;
  if (!pos.empty() && isSubcmd(toLower(pos.front()))) {
    a.subcommand = toLower(pos.front());
    if (pos.size() > 1)
      a.subArg = pos[1];
    if (pos.size() > 2)
      a.error = "too many positional arguments";
    const bool acceptsArgument = a.subcommand == "ramhog" ||
                                 a.subcommand == "cpuhog" ||
                                 a.subcommand == "restart";
    if (!acceptsArgument && !a.subArg.empty())
      a.error = "subcommand '" + a.subcommand + "' takes no argument";
  } else if (!pos.empty()) {
    // All-numeric positional arguments select processes by PID exactly
    // (e.g. "killall 1234 5678"). Any non-numeric argument falls back to the
    // legacy behavior: first argument is a name pattern, extras are an error.
    bool allNumeric = true;
    for (const auto &p : pos) {
      unsigned long long pid = 0;
      if (!parseULongLong(p, pid)) {
        allNumeric = false;
        break;
      }
      a.pids.push_back(pid);
    }
    if (!allNumeric) {
      a.pids.clear();
      a.pattern = pos.front();
      if (pos.size() > 1)
        a.error = "too many positional arguments";
    }
  }
  if (!a.subcommand.empty() &&
      (!a.cmdlinePat.empty() || !a.modulePat.empty() || !a.windowPat.empty() ||
       !a.parentSpec.empty() || !a.portSpec.empty()))
    a.error = "process filters cannot be combined with subcommands";
  if (a.top && a.subcommand != "ramhog" && a.subcommand != "cpuhog")
    a.error = "--top requires ramhog or cpuhog";
  if (sampleSpecified && a.subcommand != "cpuhog")
    a.error = "--sample requires cpuhog";
  return a;
}

// ─── Confirm + execute kills ─────────────────────────────────────────────────
static int doKill(std::vector<ProcInfo> targets, const Args &a,
                  const std::vector<ProcInfo> &allProcs) {
  if (targets.empty()) {
    puts(unreadableProcesses.empty() ? "  No matching processes found."
                                     : "  No verified matches.");
    return 0;
  }
  // Expand to process tree
  std::set<DWORD> killSet;
  if (a.killTree) {
    for (auto &p : targets) {
      auto tree = getProcessTree(p, allProcs);
      killSet.insert(tree.begin(), tree.end());
    }
  } else {
    for (auto &p : targets)
      killSet.insert(p.pid);
  }
  // Collect enriched info — skip self
  DWORD selfPid = GetCurrentProcessId();
  bool skippedSelf = killSet.count(selfPid) > 0;
  killSet.erase(selfPid);
  std::unordered_map<DWORD, const ProcInfo *> byPid;
  byPid.reserve(allProcs.size());
  for (const auto &p : allProcs)
    byPid[p.pid] = &p;
  std::vector<ProcInfo> finalList;
  for (auto pid : killSet) {
    const auto it = byPid.find(pid);
    if (it != byPid.end())
      finalList.push_back(*it->second);
  }
  if (skippedSelf)
    printf("  " YELLOW("Skipped") "  killall.exe (self)\n");
  if (finalList.empty()) {
    printf(YELLOW("  No safe matching processes remain.\n"));
    return 0;
  }

  // Default is a dry run; only -y/--yes (or its alias -f/--force) executes
  // the kill, and then without an interactive prompt.
  const bool willKill = (a.yes || a.force) && !a.dryRun;
  printf(BOLD("  Processes to %s:\n"), willKill ? "kill" : "show (dry-run)");
  for (auto &p : finalList)
    printf("    " CYAN("%-32s") " PID %-6lu  RAM %.1f MB\n", p.name.c_str(),
           (unsigned long)p.pid, p.workingSetBytes / (1024.0 * 1024.0));

  if (!willKill) {
    printf("  " YELLOW("Dry run: nothing was killed. Use -y to execute.") "\n");
    return 0;
  }

  // Compute bounded depths. A corrupt/racy parent snapshot may contain a
  // cycle, so every traversal tracks visited PIDs rather than iterating until
  // convergence.
  std::map<DWORD, DWORD> parents;
  for (const auto &p : finalList)
    parents[p.pid] = p.ppid;
  auto depthOf = [&parents](DWORD pid) {
    std::set<DWORD> visited;
    int depth = 0;
    while (visited.insert(pid).second) {
      const auto it = parents.find(pid);
      if (it == parents.end() || it->second == pid)
        break;
      pid = it->second;
      if (depth < static_cast<int>(parents.size()))
        ++depth;
    }
    return depth;
  };
  std::sort(finalList.begin(), finalList.end(),
            [&depthOf](const ProcInfo &left, const ProcInfo &right) {
              return depthOf(left.pid) > depthOf(right.pid);
            });

  const std::vector<ProcessIdentity> plan(finalList.begin(), finalList.end());
  if (!isElevated() && needsElevation(finalList) && confirmElevation())
    return launchTargetWorker(plan, L"runas");
  return executeTargets(plan);
}

// ─── Filter processes for pattern mode ───────────────────────────────────────
static std::vector<ProcInfo> filterProcs(const std::vector<ProcInfo> &all,
                                         const Args &a, bool &valid) {
  valid = false;
  int portLo = 0, portHi = 0;
  bool filterPort = !a.portSpec.empty();
  if (filterPort) {
    const auto dash = a.portSpec.find('-');
    long lo = 0;
    long hi = 0;
    const bool portValid =
        dash == std::string::npos
            ? (parseLong(a.portSpec, lo) && (hi = lo, true))
            : (dash != 0 && dash + 1 < a.portSpec.size() &&
               a.portSpec.find('-', dash + 1) == std::string::npos &&
               parseLong(a.portSpec.substr(0, dash), lo) &&
               parseLong(a.portSpec.substr(dash + 1), hi));
    if (!portValid || lo < 1 || hi > 65535 || lo > hi) {
      fprintf(stderr, RED("  Error:") " invalid port or port range '%s'\n",
              a.portSpec.c_str());
      return {};
    }
    portLo = static_cast<int>(lo);
    portHi = static_cast<int>(hi);
  }
  DWORD parentPid = 0;
  ULONGLONG parentCreated = 0;
  if (!a.parentSpec.empty()) {
    parentPid = resolveParentPid(a.parentSpec, all);
    if (parentPid == 0) {
      fprintf(stderr,
              RED("  Error:") " parent process was not found or is ambiguous: "
                              "'%s'\n",
              a.parentSpec.c_str());
      return {};
    }
    for (const auto &parent : all)
      if (parent.pid == parentPid)
        parentCreated = parent.creationTime;
  }

  Pattern namePat(a.pattern);
  Pattern cmdlinePat(a.cmdlinePat);
  Pattern modulePat(a.modulePat);
  Pattern windowPat(a.windowPat);
  if (!namePat.valid || !cmdlinePat.valid || !modulePat.valid ||
      !windowPat.valid) {
    fprintf(stderr, RED("  Error:") " invalid regular expression\n");
    return {};
  }

  valid = true;
  std::vector<ProcInfo> results;
  for (auto &p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    if (!a.pids.empty())
      if (std::find(a.pids.begin(), a.pids.end(),
                    static_cast<unsigned long long>(p.pid)) == a.pids.end())
        continue;
    if (!a.pattern.empty()) {
      if (!namePat.match(p.name) && !namePat.match(stripExeSuffix(p.name)))
        continue;
    }
    if (parentPid && (p.ppid != parentPid || !parentCreated ||
                      p.creationTime < parentCreated))
      continue;
    if (!a.cmdlinePat.empty()) {
      const auto *command = getCmdline(p.pid);
      if (!command || !cmdlinePat.match(*command))
        continue;
    }
    if (!a.modulePat.empty())
      if (!processHasModule(p.pid, modulePat))
        continue;
    if (filterPort)
      if (!processHasPort(p.pid, portLo, portHi))
        continue;
    if (!a.windowPat.empty())
      if (!processHasWindow(p.pid, windowPat))
        continue;
    results.push_back(p);
  }
  return results;
}

// ─── Subcommands ─────────────────────────────────────────────────────────────
static int cmdHung(const Args &a, const std::vector<ProcInfo> &all) {
  printf(BOLD("  Checking for hung processes...\n"));
  std::vector<ProcInfo> hung;
  for (auto &p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    if (isProcessHung(p.pid))
      hung.push_back(p);
  }
  printf("  Found %zu hung process(es).\n", hung.size());
  return doKill(hung, a, all);
}

static int cmdNetworkApps(const Args &a, const std::vector<ProcInfo> &all) {
  printf(BOLD("  Finding processes with network connections...\n"));
  std::vector<ProcInfo> net;
  for (auto &p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    if (processHasAnyNetwork(p.pid))
      net.push_back(p);
  }
  printf("  Found %zu networked process(es).\n", net.size());
  return doKill(net, a, all);
}

static int cmdRamHog(const Args &a, const std::vector<ProcInfo> &all) {
  if (a.subArg.empty()) {
    fprintf(stderr, RED("  Error:") " ramhog requires <MB> argument\n");
    return 1;
  }
  unsigned long long limitMB = 0;
  if (!parseULongLong(a.subArg, limitMB) || limitMB == 0) {
    fprintf(stderr, RED("  Error:") " invalid ramhog threshold '%s'\n",
            a.subArg.c_str());
    return 1;
  }
  constexpr unsigned long long bytesPerMB = 1024ULL * 1024ULL;
  if (limitMB >
      static_cast<unsigned long long>(std::numeric_limits<size_t>::max()) /
          bytesPerMB) {
    fprintf(stderr, RED("  Error:") " ramhog threshold is too large\n");
    return 1;
  }
  const size_t limitBytes = static_cast<size_t>(limitMB * bytesPerMB);
  printf(BOLD("  Finding processes using > %s MB RAM...\n"), a.subArg.c_str());
  std::vector<ProcInfo> hogs;
  for (auto p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    if (p.workingSetBytes > limitBytes)
      hogs.push_back(p);
  }
  std::sort(hogs.begin(), hogs.end(), [](const ProcInfo &a, const ProcInfo &b) {
    return a.workingSetBytes > b.workingSetBytes;
  });
  if (a.top > 0 && (int)hogs.size() > a.top)
    hogs.resize((size_t)a.top);
  printf("  Found %zu ram-hog process(es).\n", hogs.size());
  return doKill(hogs, a, all);
}

static int cmdCpuHog(const Args &a, const std::vector<ProcInfo> &all) {
  if (a.subArg.empty()) {
    fprintf(stderr, RED("  Error:") " cpuhog requires <percent> argument\n");
    return 1;
  }
  double limit = 0.0;
  if (!parseDouble(a.subArg, limit) || limit < 0.0) {
    fprintf(stderr, RED("  Error:") " invalid cpuhog threshold '%s'\n",
            a.subArg.c_str());
    return 1;
  }
  printf(BOLD("  Finding processes using > %.1f%% CPU...\n"), limit);
  auto cpuMap = measureCpuUsage(a.sampleSecs, all);
  if (!cpuMap) {
    fprintf(stderr, "  Cannot obtain a complete CPU sample\n");
    return 2;
  }

  std::vector<ProcInfo> hogs;
  for (auto p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    auto it = cpuMap->find(p.pid);
    if (it == cpuMap->end())
      continue;
    p.cpuPercent = it->second;
    if (p.cpuPercent >= limit)
      hogs.push_back(p);
  }
  std::sort(hogs.begin(), hogs.end(), [](const ProcInfo &a, const ProcInfo &b) {
    return a.cpuPercent > b.cpuPercent;
  });
  if (a.top > 0 && (int)hogs.size() > a.top)
    hogs.resize((size_t)a.top);
  printf("  Found %zu cpu-hog process(es).\n", hogs.size());

  return doKill(hogs, a, all);
}

static int cmdGpu(const Args &a, const std::vector<ProcInfo> &all) {
  printf(BOLD("  Finding GPU-using processes...\n"));
  std::vector<ProcInfo> gpu;
  for (auto &p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    if (processUsesGPU(p.pid))
      gpu.push_back(p);
  }
  printf("  Found %zu GPU process(es).\n", gpu.size());
  return doKill(gpu, a, all);
}

static int cmdLlm(const Args &a, const std::vector<ProcInfo> &all) {
  printf(BOLD("  Finding local LLM/AI processes...\n"));
  std::vector<ProcInfo> llms;
  for (auto &p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    if (isLLMProcess(p))
      llms.push_back(p);
  }
  printf("  Found %zu LLM process(es).\n", llms.size());
  return doKill(llms, a, all);
}

static int cmdGame(const Args &a, const std::vector<ProcInfo> &all) {
  printf(BOLD("  Finding game processes...\n"));
  std::vector<ProcInfo> games;
  for (auto &p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    if (isGameProcess(p))
      games.push_back(p);
  }
  printf("  Found %zu game process(es).\n", games.size());
  return doKill(games, a, all);
}

static int cmdRestart(const Args &a, const std::vector<ProcInfo> &all) {
  if (a.subArg.empty()) {
    fprintf(stderr, RED("  Error:") " restart requires <name>\n");
    return 1;
  }
  const std::string nameArg = stripExeSuffix(toLower(a.subArg));
  std::vector<ProcInfo> targets;
  for (auto p : all) {
    if (stripExeSuffix(p.name).find(nameArg) != std::string::npos) {
      targets.push_back(p);
    }
  }
  if (targets.empty()) {
    printf(YELLOW("  No matching process found.\n"));
    return 0;
  }
  if (targets.size() != 1) {
    fprintf(
        stderr,
        RED("  Error:") " restart requires an unambiguous process name; found "
                        "%zu matches\n",
        targets.size());
    return 1;
  }
  const auto &target = targets.front();
  auto handle = makeHandle(
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, target.pid));
  if (target.pid == GetCurrentProcessId() || !handle || !target.creationTime ||
      creationTimeOf(handle.get()) != target.creationTime) {
    fprintf(stderr, "  Cannot verify restart target identity\n");
    return 2;
  }
  const auto widePath = processPath(handle.get());
  const auto exePath = toNarrow(widePath);
  if (widePath.empty()) {
    fprintf(stderr,
            RED("  Error:") " cannot determine executable path for restart\n");
    return 1;
  }
  printf(BOLD("  Will restart: ") "%s\n", exePath.c_str());

  const int killResult = doKill(targets, a, all);
  // Restart only makes sense when the kill actually ran; a dry run (the
  // default without -y) must not relaunch the process.
  if (killResult != 0 || !(a.yes || a.force) || a.dryRun)
    return killResult;

  HINSTANCE result = ShellExecuteW(nullptr, L"open", widePath.c_str(), nullptr,
                                   nullptr, SW_SHOWNORMAL);
  if (reinterpret_cast<INT_PTR>(result) <= 32) {
    fprintf(stderr,
            RED("  Failed to restart") " %s (ShellExecute error %lld)\n",
            exePath.c_str(),
            static_cast<long long>(reinterpret_cast<INT_PTR>(result)));
    return 2;
  }
  printf(GREEN("  Restarted") " %s\n", exePath.c_str());
  return 0;
}

// ─── Main ────────────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t **wargv) {
  // Process names and messages are UTF-8; the guard restores the console
  // output code page on every exit path.
  ConsoleUtf8Guard consoleUtf8;

  // Convert wchar_t argv to UTF-8 for internal processing
  std::vector<std::string> argStorage;
  std::vector<char *> argv;
  argStorage.reserve(argc);
  for (int i = 0; i < argc; i++) {
    argStorage.push_back(toNarrow(wargv[i]));
    if (*wargv[i] && argStorage.back().empty()) {
      fprintf(stderr, "  Invalid Unicode argument\n");
      return 1;
    }
    argv.push_back(argStorage.back().data());
  }

  if (argc >= 2 && argStorage[1] == planOption) {
    std::vector<ProcessIdentity> targets;
    if (!decodeTargets(argc - 2, argv.data() + 2, targets) || !isElevated()) {
      fprintf(stderr, "  Invalid elevated execution request\n");
      return 1;
    }
    return executeTargets(targets);
  }

  Args a = parseArgs(argc, argv.data());
  if (!a.error.empty()) {
    fprintf(stderr, RED("  Error:") " %s. Use -h for help.\n", a.error.c_str());
    return 1;
  }
  if (a.version) {
    printVersion();
    return 0;
  }
  if (a.help || argc == 1) {
    printHelp();
    return 0;
  }

  std::vector<ProcInfo> allProcs;
  if (!enumProcesses(allProcs)) {
    fprintf(stderr, "  Cannot obtain a complete process identity snapshot\n");
    return 2;
  }
  const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const bool comInitialized = SUCCEEDED(comResult);

  int ret = 0;

  if (!a.subcommand.empty()) {
    if (a.subcommand == "hung")
      ret = cmdHung(a, allProcs);
    else if (a.subcommand == "networkapps")
      ret = cmdNetworkApps(a, allProcs);
    else if (a.subcommand == "ramhog")
      ret = cmdRamHog(a, allProcs);
    else if (a.subcommand == "cpuhog")
      ret = cmdCpuHog(a, allProcs);
    else if (a.subcommand == "gpu")
      ret = cmdGpu(a, allProcs);
    else if (a.subcommand == "llm")
      ret = cmdLlm(a, allProcs);
    else if (a.subcommand == "game")
      ret = cmdGame(a, allProcs);
    else if (a.subcommand == "restart")
      ret = cmdRestart(a, allProcs);
  } else {
    bool hasFilter = !a.pattern.empty() || !a.pids.empty() ||
                     !a.cmdlinePat.empty() || !a.modulePat.empty() ||
                     !a.portSpec.empty() || !a.windowPat.empty() ||
                     !a.parentSpec.empty();
    if (!hasFilter) {
      fprintf(stderr, RED("  Error:") " no pattern or filter specified. Use -h "
                                      "for help.\n");
      ret = 1;
    } else {
      bool filtersValid = false;
      auto targets = filterProcs(allProcs, a, filtersValid);
      ret = filtersValid ? doKill(targets, a, allProcs) : 1;
    }
  }

  if (comInitialized)
    CoUninitialize();
  if (!unreadableProcesses.empty()) {
    fprintf(stderr,
            "  Incomplete scan: could not inspect %zu process(es). "
            "For broader access, run from an elevated console.\n",
            unreadableProcesses.size());
    if (ret == 0)
      ret = 2;
  }
  return ret;
}
