/*
 * killall.cpp — Windows Process Termination Tool
 * Supports Windows 7 through Windows 11
 */
#define WIN32_LEAN_AND_MEAN
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

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <regex>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

// ─── Single-instance mutex ──────────────────────────────────────────────────
static HANDLE g_hSingleInstanceMutex = nullptr;

static bool ensureSingleInstance() {
  g_hSingleInstanceMutex =
      CreateMutexW(nullptr, TRUE, L"killall-win-SingleInstance");
  if (!g_hSingleInstanceMutex)
    return true; // can't create mutex → allow to run
  if (GetLastError() == ERROR_ALREADY_EXISTS) {
    CloseHandle(g_hSingleInstanceMutex);
    g_hSingleInstanceMutex = nullptr;
    fprintf(stderr, "killall is already running. Only one instance allowed.\n");
    return false;
  }
  return true;
}

// ─── ANSI colours (best-effort VT mode) ─────────────────────────────────────
static void enableColour() {
  HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
  if (hOut != INVALID_HANDLE_VALUE && hOut != nullptr) {
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode))
      SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
  HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
  if (hErr != INVALID_HANDLE_VALUE && hErr != nullptr) {
    DWORD mode = 0;
    if (GetConsoleMode(hErr, &mode))
      SetConsoleMode(hErr, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
}
#define RED(s) "\x1b[31m" s "\x1b[0m"
#define GREEN(s) "\x1b[32m" s "\x1b[0m"
#define YELLOW(s) "\x1b[33m" s "\x1b[0m"
#define CYAN(s) "\x1b[36m" s "\x1b[0m"
#define BOLD(s) "\x1b[1m" s "\x1b[0m"

// ─── Utilities ───────────────────────────────────────────────────────────────
static std::string toLower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return (char)::tolower(c); });
  return s;
}
static std::string toNarrow(const std::wstring &w) {
  if (w.empty())
    return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr,
                              nullptr);
  if (n <= 0)
    return {};
  std::string s(n - 1, 0);
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], n, nullptr, nullptr);
  return s;
}

// glob match: * = any sequence, ? = any char (case-insensitive)
static bool globMatch(const std::string &pat, const std::string &str) {
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
static bool parseLong(const std::string &s, long &out) {
  if (s.empty())
    return false;
  char *end = nullptr;
  errno = 0;
  out = strtol(s.c_str(), &end, 10);
  if (errno == ERANGE || end == s.c_str() || *end != '\0')
    return false;
  return true;
}
static bool parseULongLong(const std::string &s, unsigned long long &out) {
  if (s.empty())
    return false;
  char *end = nullptr;
  errno = 0;
  out = strtoull(s.c_str(), &end, 10);
  if (errno == ERANGE || end == s.c_str() || *end != '\0')
    return false;
  return true;
}
static bool parseDouble(const std::string &s, double &out) {
  if (s.empty())
    return false;
  char *end = nullptr;
  errno = 0;
  out = strtod(s.c_str(), &end);
  if (errno == ERANGE || end == s.c_str() || *end != '\0')
    return false;
  return true;
}

// ─── Pattern object ──────────────────────────────────────────────────────────
struct Pattern {
  enum Type { SUBSTRING, GLOB, REGEX } type;
  std::string raw;
  std::regex re;

  explicit Pattern(const std::string &pat) : type(SUBSTRING), raw(pat) {
    if (pat.size() >= 2 && pat.front() == '/' && pat.back() == '/') {
      type = REGEX;
      std::string inner = pat.substr(1, pat.size() - 2);
      try {
        re = std::regex(inner, std::regex::icase | std::regex::ECMAScript);
      } catch (...) {
        type = SUBSTRING;
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

// ─── Process info struct ─────────────────────────────────────────────────────
struct ProcInfo {
  DWORD pid = 0;
  DWORD ppid = 0;
  std::string name;
  std::string exePath;
  SIZE_T workingSetBytes = 0;
  double cpuPercent = 0.0;
};

// ─── Enumerate all processes ─────────────────────────────────────────────────
static std::vector<ProcInfo> enumProcesses() {
  std::vector<ProcInfo> procs;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return procs;
  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(pe);
  if (Process32FirstW(snap, &pe)) {
    do {
      ProcInfo p;
      p.pid = pe.th32ProcessID;
      p.ppid = pe.th32ParentProcessID;
      p.name = toLower(toNarrow(pe.szExeFile));
      procs.push_back(p);
    } while (Process32NextW(snap, &pe));
  }
  CloseHandle(snap);
  return procs;
}

// get memory and exe path
static void enrichBasic(ProcInfo &p) {
  HANDLE h =
      OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p.pid);
  if (!h)
    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
  if (!h)
    return;

  wchar_t buf[MAX_PATH * 2] = {};
  DWORD sz = (DWORD)(sizeof(buf) / sizeof(wchar_t));

  QueryFullProcessImageNameW(h, 0, buf, &sz);
  p.exePath = toNarrow(buf);

  PROCESS_MEMORY_COUNTERS pmc = {};
  if (GetProcessMemoryInfo(h, &pmc, sizeof(pmc)))
    p.workingSetBytes = pmc.WorkingSetSize;
  CloseHandle(h);
}

// ─── WMI command-line cache ──────────────────────────────────────────────────
static std::map<DWORD, std::string> g_cmdlineCache;
static bool g_cmdlineCacheBuilt = false;

static void buildCmdlineCache() {
  if (g_cmdlineCacheBuilt)
    return;
  g_cmdlineCacheBuilt = true;

  IWbemLocator *pLoc = nullptr;
  if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                              IID_IWbemLocator, (void **)&pLoc)) ||
      !pLoc)
    return;

  IWbemServices *pSvc = nullptr;
  BSTR ns = SysAllocString(L"ROOT\\CIMV2");
  HRESULT hr = pLoc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr,
                                   nullptr, &pSvc);
  SysFreeString(ns);
  if (FAILED(hr) || !pSvc) {
    pLoc->Release();
    return;
  }

  CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                    RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                    nullptr, EOAC_NONE);

  IEnumWbemClassObject *pEnum = nullptr;
  BSTR wql = SysAllocString(L"WQL");
  BSTR query =
      SysAllocString(L"SELECT ProcessId, CommandLine FROM Win32_Process");
  hr = pSvc->ExecQuery(wql, query, WBEM_FLAG_FORWARD_ONLY, nullptr, &pEnum);
  SysFreeString(wql);
  SysFreeString(query);

  if (SUCCEEDED(hr) && pEnum) {
    IWbemClassObject *obj = nullptr;
    ULONG ret = 0;
    while (pEnum->Next(WBEM_INFINITE, 1, &obj, &ret) == WBEM_S_NO_ERROR) {
      VARIANT vPid, vCmd;
      VariantInit(&vPid);
      VariantInit(&vCmd);
      obj->Get(L"ProcessId", 0, &vPid, nullptr, nullptr);
      obj->Get(L"CommandLine", 0, &vCmd, nullptr, nullptr);
      DWORD pid = (DWORD)V_UI4(&vPid);
      if (vCmd.vt == VT_BSTR && vCmd.bstrVal)
        g_cmdlineCache[pid] = toNarrow(vCmd.bstrVal);
      VariantClear(&vPid);
      VariantClear(&vCmd);
      obj->Release();
    }
    pEnum->Release();
  }
  pSvc->Release();
  pLoc->Release();
}

static std::string getCmdline(DWORD pid) {
  buildCmdlineCache();
  auto it = g_cmdlineCache.find(pid);
  return it != g_cmdlineCache.end() ? it->second : "";
}

// ─── Loaded modules ──────────────────────────────────────────────────────────
static bool processHasModule(DWORD pid, const std::string &modPat) {
  HANDLE snap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE)
    return false;
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  bool found = false;
  if (Module32FirstW(snap, &me)) {
    Pattern pat(modPat);
    do {
      std::string mn = toLower(toNarrow(me.szModule));
      std::string mp = toLower(toNarrow(me.szExePath));
      if (pat.match(mn) || pat.match(mp)) {
        found = true;
        break;
      }
    } while (Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return found;
}

// ─── Network / ports ─────────────────────────────────────────────────────────
static bool processHasPort(DWORD pid, int portLo, int portHi) {
  // TCP IPv4
  DWORD sz = 0;
  GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
  if (sz > 0) {
    std::vector<BYTE> buf(sz);
    if (GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
      auto *t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID *>(buf.data());
      for (DWORD i = 0; i < t->dwNumEntries; i++) {
        if (t->table[i].dwOwningPid == pid) {
          int lp = (int)ntohs((u_short)t->table[i].dwLocalPort);
          int rp = (int)ntohs((u_short)t->table[i].dwRemotePort);
          if ((lp >= portLo && lp <= portHi) || (rp >= portLo && rp <= portHi))
            return true;
        }
      }
    }
  }
  // TCP IPv6
  sz = 0;
  GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL,
                      0);
  if (sz > 0) {
    std::vector<BYTE> buf(sz);
    if (GetExtendedTcpTable(buf.data(), &sz, FALSE, AF_INET6,
                            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
      auto *t = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID *>(buf.data());
      for (DWORD i = 0; i < t->dwNumEntries; i++) {
        if (t->table[i].dwOwningPid == pid) {
          int lp = (int)ntohs((u_short)t->table[i].dwLocalPort);
          int rp = (int)ntohs((u_short)t->table[i].dwRemotePort);
          if ((lp >= portLo && lp <= portHi) || (rp >= portLo && rp <= portHi))
            return true;
        }
      }
    }
  }
  // UDP IPv4
  sz = 0;
  GetExtendedUdpTable(nullptr, &sz, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
  if (sz > 0) {
    std::vector<BYTE> buf(sz);
    if (GetExtendedUdpTable(buf.data(), &sz, FALSE, AF_INET,
                            UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
      auto *t = reinterpret_cast<MIB_UDPTABLE_OWNER_PID *>(buf.data());
      for (DWORD i = 0; i < t->dwNumEntries; i++) {
        if (t->table[i].dwOwningPid == pid) {
          int lp = (int)ntohs((u_short)t->table[i].dwLocalPort);
          if (lp >= portLo && lp <= portHi)
            return true;
        }
      }
    }
  }
  return false;
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
  auto *ctx = reinterpret_cast<WinEnumCtx *>(lp);
  DWORD wpid = 0;
  GetWindowThreadProcessId(hwnd, &wpid);
  if (wpid == ctx->pid) {
    wchar_t title[512] = {};
    GetWindowTextW(hwnd, title, 511);
    Pattern p(ctx->pat);
    if (p.match(toNarrow(title))) {
      ctx->found = true;
      return FALSE;
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
  auto *ctx = reinterpret_cast<HungCtx *>(lp);
  DWORD wpid = 0;
  GetWindowThreadProcessId(hwnd, &wpid);
  if (wpid == ctx->pid && IsWindow(hwnd)) {
    if (SendMessageTimeout(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG, 2000,
                           nullptr) == 0) {
      // Returns 0 on timeout/hang; GetLastError() == 0 means no other error
      if (GetLastError() == 0) {
        ctx->hung = true;
        return FALSE;
      }
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
  std::map<DWORD, ULONGLONG> t1;
  for (auto &p : allProcs) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
    if (!h)
      h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, p.pid);
    if (!h)
      continue;
    FILETIME ct, et, kt, ut;
    if (GetProcessTimes(h, &ct, &et, &kt, &ut)) {
      ULARGE_INTEGER k, u;
      k.LowPart = kt.dwLowDateTime;
      k.HighPart = kt.dwHighDateTime;
      u.LowPart = ut.dwLowDateTime;
      u.HighPart = ut.dwHighDateTime;
      t1[p.pid] = k.QuadPart + u.QuadPart;
    }
    CloseHandle(h);
  }
  ULONGLONG wall1 = GetTickCount64();
  printf(YELLOW("  Sampling CPU for %d second(s)...\n"), sampleSecs);
  Sleep((DWORD)(sampleSecs * 1000));
  ULONGLONG wall2 = GetTickCount64();
  ULONGLONG wallDiff = (wall2 - wall1) * 10000ULL; // ms -> 100ns

  std::map<DWORD, double> result;
  for (auto &p : allProcs) {
    if (t1.find(p.pid) == t1.end())
      continue;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, p.pid);
    if (!h)
      h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, p.pid);
    if (!h)
      continue;
    FILETIME ct, et, kt, ut;
    if (GetProcessTimes(h, &ct, &et, &kt, &ut)) {
      ULARGE_INTEGER k, u;
      k.LowPart = kt.dwLowDateTime;
      k.HighPart = kt.dwHighDateTime;
      u.LowPart = ut.dwLowDateTime;
      u.HighPart = ut.dwHighDateTime;
      ULONGLONG diff = (k.QuadPart + u.QuadPart) - t1[p.pid];
      if (wallDiff > 0)
        result[p.pid] = (double)diff / (double)wallDiff * 100.0;
    }
    CloseHandle(h);
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
  HANDLE snap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
  if (snap == INVALID_HANDLE_VALUE)
    return false;
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  bool found = false;
  if (Module32FirstW(snap, &me)) {
    do {
      std::string mn = toLower(toNarrow(me.szModule));
      for (int i = 0; gpuMods[i]; i++)
        if (mn == gpuMods[i]) {
          found = true;
          break;
        }
    } while (!found && Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return found;
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
  HANDLE snap =
      CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p.pid);
  if (snap == INVALID_HANDLE_VALUE)
    return false;
  MODULEENTRY32W me;
  me.dwSize = sizeof(me);
  bool found = false;
  if (Module32FirstW(snap, &me)) {
    do {
      std::string mn = toLower(toNarrow(me.szModule));
      for (int i = 0; GAME_MODS[i]; i++)
        if (mn == GAME_MODS[i]) {
          found = true;
          break;
        }
    } while (!found && Module32NextW(snap, &me));
  }
  CloseHandle(snap);
  return found;
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
static bool killPid(DWORD pid) {
  if (pid == 0 || pid == 4)
    return false;
  HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
  if (!h) {
    fprintf(stderr, "  " RED("Access denied") " PID %lu\n", (unsigned long)pid);
    return false;
  }
  bool ok = TerminateProcess(h, 1) != 0;
  CloseHandle(h);
  return ok;
}

// ─── Resolve parent name/pid ─────────────────────────────────────────────────
static DWORD resolveParentPid(const std::string &spec,
                              const std::vector<ProcInfo> &all) {
  long n = 0;
  if (parseLong(spec, n) && n > 0)
    return (DWORD)n;
  std::string lo = toLower(spec);
  for (auto &p : all)
    if (p.name.find(lo) != std::string::npos)
      return p.pid;
  return 0;
}

// ─── Args struct ─────────────────────────────────────────────────────────────
struct Args {
  std::string pattern;
  std::string subcommand;
  std::string subArg;
  bool killTree = false;
  bool force = false;
  bool dryRun = false;
  bool help = false;
  std::string cmdlinePat;
  std::string modulePat;
  std::string portSpec;
  std::string windowPat;
  std::string parentSpec;
  int top = 0;
  int sampleSecs = 2;
  int gpuThreshold = 0;
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
  puts("");
  puts(BOLD("PATTERN MATCHING"));
  puts("  name        Exact/substring match (case-insensitive)");
  puts("  part        Substring match");
  puts("  note*       Glob wildcard");
  puts("  /regex/     Regex match");
  puts("");
  puts(BOLD("OPTIONS"));
  puts("  -t, --tree               Kill process tree");
  puts("  -f, --force              Skip confirmation");
  puts("  -n, --dry-run            Show what would be killed");
  puts("  -c, --cmdline <pat>      Match command-line substring or /regex/");
  puts("  -m, --module <dll>       Match loaded module/DLL");
  puts("  -p, --port <N|A-B>       Match TCP/UDP port or range");
  puts("  -w, --window <title>     Match window title substring or /regex/");
  puts("  -P, --parent <pid|name>  Match children of a parent process");
  puts("  -N, --top <N>            Limit ramhog/cpuhog to top N offenders");
  puts("  -s, --sample <N>         CPU sampling interval (seconds)");
  puts("  -T, --threshold <N>      GPU memory threshold (MB, for gpu subcmd)");
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
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-h" || arg == "--help")
      a.help = true;
    else if (arg == "-t" || arg == "--tree")
      a.killTree = true;
    else if (arg == "-f" || arg == "--force")
      a.force = true;
    else if (arg == "-n" || arg == "--dry-run")
      a.dryRun = true;
    else if ((arg == "-c" || arg == "--cmdline") && i + 1 < argc)
      a.cmdlinePat = argv[++i];
    else if ((arg == "-m" || arg == "--module") && i + 1 < argc)
      a.modulePat = argv[++i];
    else if ((arg == "-p" || arg == "--port") && i + 1 < argc)
      a.portSpec = argv[++i];
    else if ((arg == "-w" || arg == "--window") && i + 1 < argc)
      a.windowPat = argv[++i];
    else if ((arg == "-P" || arg == "--parent") && i + 1 < argc)
      a.parentSpec = argv[++i];
    else if ((arg == "-N" || arg == "--top") && i + 1 < argc) {
      long v = 0;
      if (parseLong(argv[i + 1], v) && v > 0)
        a.top = (int)v;
      i++;
    } else if ((arg == "-s" || arg == "--sample") && i + 1 < argc) {
      long v = 0;
      if (parseLong(argv[i + 1], v) && v > 0)
        a.sampleSecs = (int)v;
      i++;
    } else if ((arg == "-T" || arg == "--threshold") && i + 1 < argc) {
      long v = 0;
      if (parseLong(argv[i + 1], v) && v >= 0)
        a.gpuThreshold = (int)v;
      i++;
    } else if (arg[0] != '-')
      pos.push_back(arg);
  }
  if (!pos.empty()) {
    if (isSubcmd(toLower(pos[0]))) {
      a.subcommand = toLower(pos[0]);
      if (pos.size() > 1)
        a.subArg = pos[1];
    } else {
      a.pattern = pos[0];
    }
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
  std::vector<ProcInfo> finalList;
  for (auto pid : killSet)
    for (auto &p : allProcs)
      if (p.pid == pid) {
        finalList.push_back(p);
        break;
      }
  for (auto &p : finalList)
    enrichBasic(p);
  if (skippedSelf)
    printf("  " YELLOW("Skipped") "  killall.exe (self)\n");

  // Print list
  printf(BOLD("  Processes to %s:\n"), a.dryRun ? "show (dry-run)" : "kill");
  for (auto &p : finalList)
    printf("    " CYAN("%-32s") " PID %-6lu  RAM %.1f MB\n", p.name.c_str(),
           (unsigned long)p.pid, p.workingSetBytes / (1024.0 * 1024.0));

  if (a.dryRun)
    return 0;

  bool proceed = a.force;
  if (!proceed) {
    printf(BOLD("  Kill %zu process(es)? [y/N] "), finalList.size());
    fflush(stdout);
    int c = getchar();
    if (c != EOF && c != '\n')
      while (getchar() != '\n')
        ; // consume rest of line
    proceed = (c == 'y' || c == 'Y');
  }
  if (!proceed) {
    printf("  Aborted.\n");
    return 0;
  }

  // Kill deepest first (children before parents), regardless of PID numbering
  std::map<DWORD, int> depth;
  for (auto &p : finalList)
    depth[p.pid] = 0;
  bool depthChanged = true;
  while (depthChanged) {
    depthChanged = false;
    for (auto &p : finalList) {
      auto it = depth.find(p.ppid);
      if (it != depth.end() && it->second >= depth[p.pid]) {
        depth[p.pid] = it->second + 1;
        depthChanged = true;
      }
    }
  }
  std::sort(finalList.begin(), finalList.end(),
            [&depth](const ProcInfo &a, const ProcInfo &b) {
              return depth[a.pid] > depth[b.pid];
            });

  int killed = 0, failed = 0;
  for (auto &p : finalList) {
    if (killPid(p.pid)) {
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
  return killed;
}

// ─── Filter processes for pattern mode ───────────────────────────────────────
static std::vector<ProcInfo> filterProcs(const std::vector<ProcInfo> &all,
                                         const Args &a) {
  int portLo = 0, portHi = 0;
  bool filterPort = !a.portSpec.empty();
  if (filterPort) {
    auto dash = a.portSpec.find('-');
    if (dash != std::string::npos) {
      long lo = 0, hi = 0;
      if (parseLong(a.portSpec.substr(0, dash), lo) &&
          parseLong(a.portSpec.substr(dash + 1), hi)) {
        portLo = (int)lo;
        portHi = (int)hi;
      }
    } else {
      long v = 0;
      if (parseLong(a.portSpec, v))
        portLo = portHi = (int)v;
    }
  }
  DWORD parentPid = 0;
  if (!a.parentSpec.empty())
    parentPid = resolveParentPid(a.parentSpec, all);

  Pattern namePat(a.pattern);
  Pattern cmdlinePat(a.cmdlinePat);

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
  size_t limitBytes = (size_t)(limitMB * 1024ULL * 1024ULL);
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
  int secs = a.sampleSecs > 0 ? a.sampleSecs : 2;
  printf(BOLD("  Finding processes using > %.1f%% CPU...\n"), limit);
  auto cpuMap = measureCpuUsage(secs, all);

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

  // Show CPU column before delegating kill logic to doKill
  printf(BOLD("  Processes to %s:\n"), a.dryRun ? "show (dry-run)" : "kill");
  for (auto &p : hogs)
    printf("    " CYAN("%-32s") " PID %-6lu  CPU %.1f%%\n", p.name.c_str(),
           (unsigned long)p.pid, p.cpuPercent);

  if (a.dryRun)
    return 0;

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
  std::string exePath = targets[0].exePath;
  printf(BOLD("  Will restart: ") "%s\n", exePath.c_str());

  Args ka = a;
  ka.force = true;
  doKill(targets, ka, all);
  Sleep(1200);

  if (!exePath.empty()) {
    int wn = MultiByteToWideChar(CP_UTF8, 0, exePath.c_str(), -1, nullptr, 0);
    std::wstring wexePath(wn > 0 ? wn - 1 : 0, 0);
    if (wn > 0)
      MultiByteToWideChar(CP_UTF8, 0, exePath.c_str(), -1, &wexePath[0], wn);
    HINSTANCE r = ShellExecuteW(nullptr, L"open", wexePath.c_str(), nullptr,
                                nullptr, SW_SHOWNORMAL);
    if ((intptr_t)r > 32)
      printf(GREEN("  Restarted") " %s\n", exePath.c_str());
    else
      fprintf(stderr, RED("  Failed to restart") " %s\n", exePath.c_str());
  }
  return 0;
}

// ─── Main ────────────────────────────────────────────────────────────────────
int wmain(int argc, wchar_t **wargv) {
  enableColour();

  if (!ensureSingleInstance())
    return 1;

  // Convert wchar_t argv to UTF-8 for internal processing
  std::vector<std::string> argStorage;
  std::vector<char *> argv;
  argStorage.reserve(argc);
  for (int i = 0; i < argc; i++) {
    argStorage.push_back(toNarrow(wargv[i]));
    argv.push_back(&argStorage.back()[0]);
  }

  // --version / -V exits immediately before any other processing
  for (int i = 1; i < argc; i++) {
    std::string arg = toNarrow(wargv[i]);
    if (arg == "-V" || arg == "--version") {
      printVersion();
      if (g_hSingleInstanceMutex)
        CloseHandle(g_hSingleInstanceMutex);
      return 0;
    }
  }

  Args a = parseArgs(argc, argv.data());

  if (a.help || argc == 1) {
    printHelp();
    if (g_hSingleInstanceMutex)
      CloseHandle(g_hSingleInstanceMutex);
    return 0;
  }

  // COM for WMI (may fail silently on systems without WMI)
  CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

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
      auto targets = filterProcs(allProcs, a);
      ret = doKill(targets, a, allProcs);
    }
  }

  CoUninitialize();
  if (g_hSingleInstanceMutex)
    CloseHandle(g_hSingleInstanceMutex);
  return ret;
}
