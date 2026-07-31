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
#include <psapi.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <wbemidl.h>

#include "version.hpp"
#include "pattern.hpp"

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
#include <regex>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
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
struct ProcInfo {
  DWORD pid = 0;
  DWORD ppid = 0;
  std::string name;
  std::string exePath;
  SIZE_T workingSetBytes = 0;
  double cpuPercent = 0.0;
  ULONGLONG creationTime = 0;
};

// ─── Enumerate all processes ─────────────────────────────────────────────────
static std::vector<ProcInfo> enumProcesses() {
  std::vector<ProcInfo> procs;
  auto snap = makeHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
  if (!snap) {
    fprintf(stderr,
            RED("  Warning:") " process snapshot failed (Windows error %lu); "
                              "no processes will be matched\n",
            static_cast<unsigned long>(GetLastError()));
    return procs;
  }
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(static_cast<HANDLE>(snap.get()), &pe)) {
    do {
      ProcInfo p;
      p.pid = pe.th32ProcessID;
      p.ppid = pe.th32ParentProcessID;
      p.name = toLower(toNarrow(pe.szExeFile));
      procs.push_back(p);
    } while (Process32NextW(static_cast<HANDLE>(snap.get()), &pe));
  }
  return procs;
}

// get memory and exe path
static void enrichBasic(ProcInfo &p) {
  auto queryHandle =
      makeHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid));
  if (queryHandle) {
    std::vector<wchar_t> path(32768);
    DWORD size = static_cast<DWORD>(path.size());
    if (QueryFullProcessImageNameW(static_cast<HANDLE>(queryHandle.get()), 0,
                                   path.data(), &size))
      p.exePath = toNarrow(std::wstring(path.data(), size));

    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetProcessTimes(static_cast<HANDLE>(queryHandle.get()), &created,
                        &exited, &kernel, &user)) {
      ULARGE_INTEGER value{};
      value.LowPart = created.dwLowDateTime;
      value.HighPart = created.dwHighDateTime;
      p.creationTime = value.QuadPart;
    }
  }

  auto memoryHandle = makeHandle(
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.pid));
  if (memoryHandle) {
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(static_cast<HANDLE>(memoryHandle.get()), &pmc,
                             sizeof(pmc)))
      p.workingSetBytes = pmc.WorkingSetSize;
  }
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

static void buildCmdlineCache() {
  if (g_cmdlineCacheBuilt || g_cmdlineCacheFailed)
    return;
  // g_cmdlineCacheBuilt is only set on success so a transient WMI failure is
  // retried on the next getCmdline() call instead of silently caching nothing.

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
    if (hr == WBEM_S_TIMEDOUT || returned == 0)
      break;
    if (FAILED(hr) || !object)
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
      g_cmdlineCache[pid] = toNarrow(commandValue.bstrVal);
    }
    VariantClear(&pidValue);
    VariantClear(&commandValue);
  }
  g_cmdlineCacheBuilt = true;
}

static std::string getCmdline(DWORD pid) {
  buildCmdlineCache();
  if (!g_cmdlineCacheBuilt && g_cmdlineCacheFailed) {
    static bool warned = false;
    if (!warned) {
      warned = true;
      fprintf(stderr,
              RED("  Warning:") " WMI command-line query failed; --cmdline "
                                "matching will return no results\n");
    }
  }
  auto it = g_cmdlineCache.find(pid);
  return it != g_cmdlineCache.end() ? it->second : "";
}

// ─── Loaded modules ──────────────────────────────────────────────────────────
// Iterates loaded modules of pid; returns true as soon as fn returns true.
template <typename Fn>
static bool forEachModule(DWORD pid, Fn &&fn) {
  auto snap = makeHandle(
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
  if (!snap)
    return false;
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
  return found;
}

static bool processHasModule(DWORD pid, const std::string &modPat) {
  Pattern pat(modPat);
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
  for (DWORD i = 0; i < table->dwNumEntries; ++i) {
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
struct WinEnumCtx {
  DWORD pid;
  std::string pat;
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
    if (GetWindowTextW(hwnd, title, 511) > 0) {
      Pattern p(ctx->pat);
      if (p.match(toNarrow(title))) {
        ctx->found = true;
        return FALSE;
      }
    }
  }
  return TRUE;
}
static bool processHasWindow(DWORD pid, const std::string &pat) {
  WinEnumCtx ctx = {pid, pat, false};
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
    if (SendMessageTimeoutW(hwnd, WM_NULL, 0, 0,
                            SMTO_ABORTIFHUNG | SMTO_BLOCK, 2000, &result) ==
        0) {
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
static std::map<DWORD, double>
measureCpuUsage(int sampleSecs, const std::vector<ProcInfo> &allProcs) {
  struct CpuSnapshot {
    ULONGLONG creation = 0;
    ULONGLONG cpu = 0;
  };
  std::map<DWORD, CpuSnapshot> first;
  for (const auto &process : allProcs) {
    auto handle = makeHandle(
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid));
    if (!handle)
      continue;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetProcessTimes(static_cast<HANDLE>(handle.get()), &created, &exited,
                        &kernel, &user)) {
      ULARGE_INTEGER c{}, k{}, u{};
      c.LowPart = created.dwLowDateTime;
      c.HighPart = created.dwHighDateTime;
      k.LowPart = kernel.dwLowDateTime;
      k.HighPart = kernel.dwHighDateTime;
      u.LowPart = user.dwLowDateTime;
      u.HighPart = user.dwHighDateTime;
      first[process.pid] = {c.QuadPart, k.QuadPart + u.QuadPart};
    }
  }
  ULONGLONG wallStart = 0;
  if (!QueryUnbiasedInterruptTime(&wallStart))
    wallStart = GetTickCount64() * 10000ULL; // fallback: ms -> 100ns
  printf(YELLOW("  Sampling CPU for %d second(s)...\n"), sampleSecs);
  Sleep(static_cast<DWORD>(sampleSecs) * 1000U);
  ULONGLONG wallEnd = 0;
  if (!QueryUnbiasedInterruptTime(&wallEnd))
    wallEnd = GetTickCount64() * 10000ULL;
  // QueryUnbiasedInterruptTime is in 100ns units like GetProcessTimes, and it
  // keeps counting while the machine sleeps (GetTickCount64 does not).
  const ULONGLONG wallDiff = wallEnd - wallStart;

  std::map<DWORD, double> result;
  for (const auto &process : allProcs) {
    const auto previous = first.find(process.pid);
    if (previous == first.end())
      continue;
    auto handle = makeHandle(
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process.pid));
    if (!handle)
      continue;
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(static_cast<HANDLE>(handle.get()), &created, &exited,
                         &kernel, &user))
      continue;
    ULARGE_INTEGER c{}, k{}, u{};
    c.LowPart = created.dwLowDateTime;
    c.HighPart = created.dwHighDateTime;
    k.LowPart = kernel.dwLowDateTime;
    k.HighPart = kernel.dwHighDateTime;
    u.LowPart = user.dwLowDateTime;
    u.HighPart = user.dwHighDateTime;
    const ULONGLONG cpu = k.QuadPart + u.QuadPart;
    if (wallDiff > 0 && c.QuadPart == previous->second.creation &&
        cpu >= previous->second.cpu)
      result[process.pid] = static_cast<double>(cpu - previous->second.cpu) /
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
  std::string n = toLower(p.name);
  if (n.size() > 4 && n.substr(n.size() - 4) == ".exe")
    n = n.substr(0, n.size() - 4);
  for (int i = 0; LLM_KEYWORDS[i]; i++)
    if (n.find(LLM_KEYWORDS[i]) != std::string::npos)
      return true;
  std::string cmd = toLower(getCmdline(p.pid));
  if (cmd.empty())
    return false;
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
  std::string n = toLower(p.name);
  if (n.size() > 4 && n.substr(n.size() - 4) == ".exe")
    n = n.substr(0, n.size() - 4);
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
static std::set<DWORD> getProcessTree(DWORD rootPid,
                                      const std::vector<ProcInfo> &all) {
  std::set<DWORD> tree;
  std::vector<DWORD> queue = {rootPid};
  while (!queue.empty()) {
    DWORD cur = queue.back();
    queue.pop_back();
    if (!tree.insert(cur).second)
      continue;
    for (auto &p : all)
      if (p.ppid == cur && p.pid != cur)
        queue.push_back(p.pid);
  }
  return tree;
}

// ─── Kill a PID ──────────────────────────────────────────────────────────────
static bool isProtectedProcess(const ProcInfo &process, HANDLE handle) {
  // process.name is already lower-cased by enumProcesses().
  static const std::set<std::string> protectedNames = {
      "csrss.exe",       "lsass.exe",      "services.exe",
      "smss.exe",        "wininit.exe",    "winlogon.exe",
      "registry",        "secure system",  "memory compression"};
  if (process.pid == 0 || process.pid == 4 ||
      protectedNames.count(process.name) != 0)
    return true;

  using IsProcessCriticalFn = BOOL(WINAPI *)(HANDLE, PBOOL);
  const HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
  const auto isProcessCritical =
      kernel ? reinterpret_cast<IsProcessCriticalFn>(
                   GetProcAddress(kernel, "IsProcessCritical"))
             : nullptr;
  BOOL critical = FALSE;
  return isProcessCritical && isProcessCritical(handle, &critical) && critical;
}

static bool killProcess(const ProcInfo &process) {
  auto handle = makeHandle(OpenProcess(
      PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
      FALSE, process.pid));
  if (!handle) {
    fprintf(stderr, "  Cannot open PID %lu (Windows error %lu)\n",
            static_cast<unsigned long>(process.pid),
            static_cast<unsigned long>(GetLastError()));
    return false;
  }

  FILETIME created{}, exited{}, kernel{}, user{};
  ULARGE_INTEGER creation{};
  if (!GetProcessTimes(static_cast<HANDLE>(handle.get()), &created, &exited,
                       &kernel, &user)) {
    fprintf(stderr, "  Cannot verify PID %lu identity (Windows error %lu)\n",
            static_cast<unsigned long>(process.pid),
            static_cast<unsigned long>(GetLastError()));
    return false;
  }
  creation.LowPart = created.dwLowDateTime;
  creation.HighPart = created.dwHighDateTime;
  if (process.creationTime == 0) {
    fprintf(stderr,
            "  Cannot verify PID %lu creation time (insufficient "
            "permissions?); refusing to kill\n",
            static_cast<unsigned long>(process.pid));
    return false;
  }
  if (creation.QuadPart != process.creationTime) {
    fprintf(stderr, "  Refusing PID %lu: process identity changed\n",
            static_cast<unsigned long>(process.pid));
    return false;
  }
  if (isProtectedProcess(process, static_cast<HANDLE>(handle.get()))) {
    fprintf(stderr, "  Refusing to terminate protected process PID %lu\n",
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
  std::string lower = toLower(spec);
  // Accept both "explorer" and "explorer.exe" for symmetry with the name
  // matching used everywhere else.
  if (lower.size() > 4 && lower.compare(lower.size() - 4, 4, ".exe") == 0)
    lower.resize(lower.size() - 4);
  DWORD result = 0;
  for (const auto &process : all) {
    std::string name = process.name;
    if (name.size() > 4 && name.compare(name.size() - 4, 4, ".exe") == 0)
      name.resize(name.size() - 4);
    if (name == lower) {
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
  std::string subcommand;
  std::string subArg;
  std::string error;
  bool killTree = false;
  bool yes = false;    // -y/--yes: execute the kill
  bool force = false;  // -f/--force: alias of -y (backwards compatibility)
  bool dryRun = false; // -n/--dry-run: explicit dry run (default anyway)
  bool help = false;
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
  puts("  killall <subcommand> [options]");
  puts("  (Default: dry-run; add -y to actually kill)");
  puts("");
  puts(BOLD("PATTERN MATCHING"));
  puts("  name        Exact/substring match (case-insensitive)");
  puts("  part        Substring match");
  puts("  note*       Glob wildcard");
  puts("  /regex/     Regex match");
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
  auto requireValue = [&](int &index, const std::string &option,
                          std::string &destination) {
    if (index + 1 >= argc || argv[index + 1][0] == '\0') {
      a.error = "option '" + option + "' requires a value";
      return false;
    }
    destination = argv[++index];
    return true;
  };

  for (int i = 1; i < argc && a.error.empty(); ++i) {
    const std::string arg = argv[i];
    if (arg == "--") {
      while (++i < argc)
        pos.emplace_back(argv[i]);
      break;
    } else if (arg == "-h" || arg == "--help")
      a.help = true;
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
      if (arg == "-s" || arg == "--sample")
        a.sampleSecs = static_cast<int>(parsed);
      else
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
    a.pattern = pos.front();
    if (pos.size() > 1)
      a.error = "too many positional arguments";
  }
  return a;
}

// ─── Confirm + execute kills ─────────────────────────────────────────────────
static int doKill(std::vector<ProcInfo> targets, const Args &a,
                  const std::vector<ProcInfo> &allProcs) {
  if (targets.empty()) {
    printf(YELLOW("  No matching processes found.\n"));
    return 0;
  }
  // Expand to process tree
  std::set<DWORD> killSet;
  if (a.killTree) {
    for (auto &p : targets) {
      auto tree = getProcessTree(p.pid, allProcs);
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
  for (auto &p : finalList)
    enrichBasic(p);
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

  int killed = 0, failed = 0;
  for (auto &p : finalList) {
    if (killProcess(p)) {
      printf("  " GREEN("Killed") "  %-32s PID %lu\n", p.name.c_str(),
             (unsigned long)p.pid);
      killed++;
    } else {
      printf("  " RED("Failed") "  %-32s PID %lu\n", p.name.c_str(),
             (unsigned long)p.pid);
      failed++;
    }
  }
  printf(BOLD("  Done:") " %d killed, %d failed.\n", killed, failed);
  return failed == 0 ? 0 : 2;
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
  if (!a.parentSpec.empty()) {
    parentPid = resolveParentPid(a.parentSpec, all);
    if (parentPid == 0) {
      fprintf(stderr,
              RED("  Error:") " parent process was not found or is ambiguous: "
                              "'%s'\n",
              a.parentSpec.c_str());
      return {};
    }
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
    if (!a.pattern.empty()) {
      std::string noExt = p.name;
      if (noExt.size() > 4 && noExt.substr(noExt.size() - 4) == ".exe")
        noExt = noExt.substr(0, noExt.size() - 4);
      if (!namePat.match(p.name) && !namePat.match(noExt))
        continue;
    }
    if (!a.cmdlinePat.empty()) {
      if (!cmdlinePat.match(getCmdline(p.pid)))
        continue;
    }
    if (!a.modulePat.empty())
      if (!processHasModule(p.pid, a.modulePat))
        continue;
    if (filterPort)
      if (!processHasPort(p.pid, portLo, portHi))
        continue;
    if (!a.windowPat.empty())
      if (!processHasWindow(p.pid, a.windowPat))
        continue;
    if (parentPid != 0)
      if (p.ppid != parentPid)
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
    enrichBasic(p);
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

  std::vector<ProcInfo> hogs;
  for (auto p : all) {
    if (p.pid == 0 || p.pid == 4)
      continue;
    auto it = cpuMap.find(p.pid);
    if (it == cpuMap.end())
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
  std::string nameArg = toLower(a.subArg);
  // Accept both "explorer" and "explorer.exe" for symmetry with the name
  // matching used everywhere else.
  if (nameArg.size() > 4 && nameArg.substr(nameArg.size() - 4) == ".exe")
    nameArg = nameArg.substr(0, nameArg.size() - 4);
  std::vector<ProcInfo> targets;
  for (auto p : all) {
    std::string n = p.name;
    if (n.size() > 4 && n.substr(n.size() - 4) == ".exe")
      n = n.substr(0, n.size() - 4);
    if (n.find(nameArg) != std::string::npos) {
      enrichBasic(p);
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
  const std::string exePath = targets.front().exePath;
  if (exePath.empty()) {
    fprintf(stderr, RED("  Error:") " cannot determine executable path\n");
    return 1;
  }
  printf(BOLD("  Will restart: ") "%s\n", exePath.c_str());

  const int killResult = doKill(targets, a, all);
  // Restart only makes sense when the kill actually ran; a dry run (the
  // default without -y) must not relaunch the process.
  if (killResult != 0 || !(a.yes || a.force) || a.dryRun)
    return killResult;

  const std::wstring widePath = toWide(exePath);
  if (widePath.empty()) {
    fprintf(stderr, RED("  Error:") " executable path is not valid UTF-8\n");
    return 1;
  }
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
    argv.push_back(argStorage.back().data());
  }

  // --version / -V exits immediately before any other processing; a "--"
  // separator means the remaining arguments are positional, not options.
  for (int i = 1; i < argc; i++) {
    std::string arg = toNarrow(wargv[i]);
    if (arg == "--")
      break;
    if (arg == "-V" || arg == "--version") {
      printVersion();
      return 0;
    }
  }

  Args a = parseArgs(argc, argv.data());
  if (!a.error.empty()) {
    fprintf(stderr, RED("  Error:") " %s. Use -h for help.\n", a.error.c_str());
    return 1;
  }
  if (a.help || argc == 1) {
    printHelp();
    return 0;
  }

  const HRESULT comResult = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  const bool comInitialized = SUCCEEDED(comResult);

  auto allProcs = enumProcesses();
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
    bool hasFilter = !a.pattern.empty() || !a.cmdlinePat.empty() ||
                     !a.modulePat.empty() || !a.portSpec.empty() ||
                     !a.windowPat.empty() || !a.parentSpec.empty();
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
  return ret;
}
