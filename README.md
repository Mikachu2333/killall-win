# killall — Windows Process Termination Tool

A fast, feature-rich `killall` command for Windows 7 through Windows 11, written in C++.
Kill processes by name, pattern, port, DLL, window title, CPU/RAM usage, and more.

---

## Features

| Capability | Description |
|---|---|
| Pattern matching | Exact, substring, glob (`*`/`?`), regex (`/pattern/`) |
| Process tree | Kill a process and all its children with `--tree` |
| Port targeting | Kill whatever is holding a port or port range |
| DLL/module matching | Kill processes that have a specific DLL loaded |
| Window title | Kill by visible window title |
| CPU hog | Sample and kill processes exceeding a CPU threshold |
| RAM hog | Kill processes over a memory limit |
| Hung apps | Detect and kill frozen/unresponsive windows |
| LLM/AI killer | Kills Ollama, LM Studio, Fooocus, KoboldCPP, etc. |
| Game killer | Kills Steam, Epic, Xbox, Ubisoft Connect, and running games |
| Restart | Kill and relaunch a process |
| Self-protection | Never kills itself |
| Safe by default | Dry-run unless `-y` is given |
| Auto-elevation | Prompts to retry with administrator rights when needed |
| Safe output | Plain console output with a dry-run safety net (including Windows 7 and redirected logs) |

---

## Quick Start

Download `killall.exe` from [Releases](../../releases), drop it anywhere in your PATH, done.

Or build from source — see [Building](#building).

---

## Usage

```
killall <pattern> [options]
killall <subcommand> [options]
```

By default `killall` only **lists** matching processes (dry-run) and never kills anything. Add `-y` (or the legacy alias `-f`) to actually execute the kill.

### Pattern Matching

| Syntax | Type | Example |
|---|---|---|
| `notepad` | Substring (case-insensitive) | matches `notepad.exe` |
| `note*` | Glob wildcard | matches `notepad.exe`, `notepadpp.exe` |
| `/^steam/` | Regex | matches processes starting with `steam` |

### Options

```
-t, --tree            Kill process and all its children
-y, --yes             Execute the kill (default is dry-run)
-f, --force           Alias of --yes (kept for compatibility)
-n, --dry-run         Explicit dry-run (this is the default behavior)
--cmdline <pat>       Match command-line substring or /regex/
--module <dll>        Match processes with a specific DLL loaded
--port <N|A-B>        Match a local TCP/UDP port or range
--window <title>      Match by visible window title (substring or /regex/)
--parent <pid|name>   Match children of a specific parent process
--top <N>             Limit ramhog/cpuhog to top N offenders
--sample <N>          CPU sampling duration in seconds (default: 2)
-h, --help            Show help
```

### Subcommands

```
hung                  Kill hung/frozen applications
networkapps           Kill all processes with network connections
ramhog <MB>           Kill processes using more than N MB of RAM
cpuhog <percent>      Kill processes using more than N% CPU (per core)
gpu                   Kill processes with known GPU API modules loaded
llm                   Kill local AI/LLM processes
game                  Kill games, launchers, and gaming services
restart <name>        Kill a process then relaunch it
```

---

## Examples

```bat
:: Kill all Notepad windows
killall notepad -y

:: Kill Chrome and every child process it spawned
killall chrome --tree -y

:: See what's on port 8080 (dry-run is the default)
killall --port 8080

:: Kill anything holding a port or port range
killall --port 8080 -y
killall --port 3000-3010 -y

:: Kill by command-line content (useful for Python scripts)
killall --cmdline fooocus -y
killall --cmdline /server\.py$/ -y

:: Kill processes with a specific DLL loaded
killall --module msedge.dll

:: Kill by window title
killall --window "Untitled" -y

:: Kill all children of a process
killall --parent explorer

:: Kill the top 3 RAM hogs over 500 MB
killall ramhog 500 --top 3

:: Kill CPU hogs over 80% (per core), sampling for 3 seconds
killall cpuhog 80 --sample 3 --top 5 -y

:: Kill all local LLMs (Ollama, LM Studio, KoboldCPP, Fooocus, etc.)
killall llm -y

:: Kill all games and launchers (Steam, Epic, Xbox, Ubisoft, etc.)
killall game -y

:: Kill and restart a process
killall restart explorer -y

:: Kill hung/frozen applications
killall hung -y
```

---

## LLM / AI Detection

`killall llm` detects AI processes by:

- **Process name:** `ollama`, `lm studio`, `koboldcpp`, `jan`, `gpt4all`, `oobabooga`, `localai`, `vllm`, `whisper`, and more
- **Command line:** `.gguf`, `.ggml`, `.safetensors`, `.ckpt` model files
- **Command line:** `fooocus`, `comfyui`, `webui.py`, `stable-diffusion`, `invokeai`, `kohya`, and others

## Game Detection

`killall game` detects games by:

- **Process name:** `steam`, `epicgameslauncher`, `xboxpcapp`, `upc`, `galaxyclient`, `blizzard`, `eadesktop`, `riotclientservices`, `minecraft`, and more
- **Loaded DLLs:** `steam_api64.dll`, `unityplayer.dll`, `easyanticheat.dll`, `nvngx_dlss.dll`, `bink2w64.dll`, and others

---

## Building

### Requirements

- Windows 7 through Windows 11
- [Visual Studio 2022](https://visualstudio.microsoft.com/downloads/) with **Desktop development with C++** workload
  (or just the free **Build Tools for Visual Studio 2022**)

### Build

```bat
git clone https://github.com/YOUR_USERNAME/killall-windows
cd killall-windows
cmake -B build/x64 -A x64
cmake --build build/x64 --config Release
```

### Install

```bat
:: Run as Administrator for system-wide install (System32)
:: Or run as normal user for per-user install (~\AppData\Local\Programs\killall)
install.bat
```

---

## How It Works

| Feature | Windows API Used |
|---|---|
| Process enumeration | `CreateToolhelp32Snapshot` |
| Process termination | `TerminateProcess` |
| Process tree | `PROCESSENTRY32.th32ParentProcessID` traversal |
| Command line | WMI `Win32_Process.CommandLine` |
| Loaded modules | `CreateToolhelp32Snapshot (TH32CS_SNAPMODULE)` |
| Network ports | `GetExtendedTcpTable` / `GetExtendedUdpTable` (local TCP/UDP IPv4 and IPv6) |
| Window title | `EnumWindows` + `GetWindowText` |
| Hung detection | `SendMessageTimeout(WM_NULL, 2000ms)` |
| Memory usage | `GetProcessMemoryInfo` |
| CPU usage | Two-snapshot `GetProcessTimes` delta |
| GPU detection | Heuristic check for loaded D3D/DXGI/Vulkan/CUDA DLLs; this does not measure GPU memory or active utilization |
| Process restart | `QueryFullProcessImageNameW` + `ShellExecuteW` |

---

## Notes

- Processes running as **SYSTEM** (e.g. `gamingservices.exe`, `steamservice.exe`) require running killall as **Administrator** to terminate
- `killall` never kills its own process (self-protection built in)
- All pattern matching is case-insensitive
- `cpuhog` reports total process CPU time divided by wall-clock time; a multithreaded process can exceed 100%
- Port matching uses local ports only; remote service ports are intentionally ignored to prevent broad accidental matches
- Critical Windows processes are refused even when killall is elevated
- When a kill target cannot be opened for termination (e.g. SYSTEM processes), killall asks once whether to relaunch itself with administrator rights (UAC). The prompt only appears on an interactive console, never for dry runs, and never when already elevated

---

## License

MIT
