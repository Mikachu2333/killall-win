## Build

CMake project (C++20, MSVC). Open the folder in VSCode with the CMake Tools extension, or build manually:

```bash
cmake -B build/x64 -A x64
cmake --build build/x64 --config Release
cmake -B build/x86 -A Win32
cmake --build build/x86 --config Release
```

Or single-shot from VS Developer Command Prompt:

```powershell
cl /EHsc /O2 killall.cpp /Fe:killall.exe
```

**Linking**: Release uses static VCRuntime (`/MT`); Debug uses dynamic (`/MDd`). All system libs are declared via `#pragma comment(lib, ...)` — no manual linker flags needed.

**Target compatibility**: Windows 7 through Windows 11. Compiles with `_WIN32_WINNT 0x0601`. Uses `wmain` for Unicode command-line input (Chinese/emoji safe).

## Architecture

Single-file project at [killall.cpp](killall.cpp). A `killall`-like Windows process termination tool — find and kill processes by name, pattern, or heuristic category.

**Three-tier pattern matching** (`Pattern` struct):

1. Substring (default) — case-insensitive
2. Glob — `*` and `?` wildcards
3. Regex — `/pattern/` syntax with `std::regex::ECMAScript | icase`

**Process enumeration and filtering pipeline:**

1. `enumProcesses()` — `SystemProcessInformation` supplies PID, creation time, name, parent, CPU times and working set in one snapshot. Its fixed prefix on Windows 7+ places creation, user and kernel times after the first 24 bytes of `Reserved1`. `Reserved2` holds the parent PID. The reader checks its own creation time against `GetProcessTimes` before accepting the snapshot.
2. `processPath()` — reads the executable path from the process handle used to verify identity
3. `filterProcs()` — applies name, cmdline (WMI cache), module, port, window-title, and parent filters
4. `doKill()` — prints the targets and orders children before parents. The default is a dry run. `-y/--yes` (alias `-f`) executes. An interactive UAC retry uses `ShellExecuteExW` with the fixed identities from `target_plan.hpp`. The worker verifies `TokenElevation` and executes those identities directly. The parent propagates its exit code.

**WMI command-line cache**: Lazily built via `IWbemServices::ExecQuery`. COM initialized in `wmain()` with matching `CoUninitialize()` on exit.

**Network detection**: Queries `GetExtendedTcpTable` (IPv4 + IPv6) and `GetExtendedUdpTable` (IPv4).

**Subcommands** — each is a heuristic category:

- `hung` — `SendMessageTimeout(WM_NULL, SMTO_ABORTIFHUNG, 2000ms)` on process windows
- `networkapps` — any process with a TCP/UDP port open
- `ramhog <MB>` — `WorkingSetSize > threshold`, sorted descending, optional `--top N`
- `cpuhog <percent>` — two-snapshot CPU measurement by PID and creation time with configurable sleep (`--sample`), optional `--top N`
- `gpu` — checks loaded modules against known GPU DLLs
- `llm` — matches process name + command-line against AI/LLM keywords
- `game` — matches process name + loaded modules against game launcher/SDK names
- `restart <name>` — the original caller uses `ShellExecuteW` to relaunch the verified executable after successful termination

**Safe numeric parsing**: `parseLong()`, `parseULongLong()`, `parseDouble()` — wrappers around `strtol`/`strtoull`/`strtod` with `errno` and end-pointer validation. Used for all CLI numeric arguments.
