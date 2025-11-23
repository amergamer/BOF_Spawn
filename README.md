# BOF Spawn - Process Injection 

## Update

### 11/23/25

- Update `Makefile` and add `.gitkeep` in `Bin/` and `Bin/temp`, thanks @0xTriboulet for issues
- Update `BOF_spawn.cna` to fix initialization, thanks @D1sAbl4 for issues

## Overview

**BOF Spawn** is a Beacon Object File for Cobalt Strike that implements process spawning and shellcode injection Draugr stack spoofing with indirect syscalls. This tool combines multiple evasion techniques to bypass userland hooks, call stack analysis, and memory scanners.

**Architecture**: x64 only

### Core Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    Cobalt Strike Beacon                      │
│                    (Parent Process)                          │
└────────────────────────┬─────────────────────────────────────┘
                         │
                         │ beacon_inline_execute()
                         │
                         ▼
          ┌──────────────────────────────┐
          │      BOF Spawn (Bof.c)       │
          │  ┌────────────────────────┐  │
          │  │  VxTable Initialization │ │
          │  │  (Syscall Resolution)   │ │
          │  └──────────┬─────────────┘  │
          │             │                │
          │  ┌──────────▼─────────────┐  │
          │  │  Draugr Framework      │  │
          │  │  - Stack Spoofing      │  │
          │  │  - Indirect Syscalls   │  │
          │  └──────────┬─────────────┘  │
          │             │                │
          │  ┌──────────▼─────────────┐  │
          │  │  SpawnAndRun()         │  │
          │  │  - Process Creation    │  │
          │  │  - Memory Allocation   │  │
          │  │  - Shellcode Injection │  │
          │  │  - Execution           │  │
          │  └────────────────────────┘  │
          └──────────────┬───────────────┘
                         │
                         ▼
          ┌──────────────────────────────┐
          │     Target Process           │
          │  (Suspended → Executing)     │
          │                              │
          │  ┌────────────────────────┐  │
          │  │  Injected Shellcode    │  │
          │  └────────────────────────┘  │
          └──────────────────────────────┘
```

## Configuration Options

The BOF provides extensive customization through the CNA script configuration dialog:

| Option | Description | Format/Notes |
|--------|-------------|--------------|
| **Process Name** | Executable path to spawn | NT path format: `\??\C:\Windows\System32\rundll32.exe` |
| **Working Directory** | Current directory for spawned process | Standard path: `C:\Windows\System32` |
| **PPID Spoof Process** | Parent process name for PPID spoofing | Process name only (e.g., `explorer.exe`) |
| **Command Line** | Arguments for spawned process | Full command line string |
| **Block DLL Policy** | Restrict to Microsoft-signed DLLs only | Boolean |
| **Disable CFG** | Disable Control Flow Guard | Boolean - Required for callback execution method |
| **Use RWX** | Allocate memory as RWX vs RW→RX | Boolean - RW→RX recommended for stealth |
| **Execution Method** | Shellcode execution technique | See section below |

**Note on Process Path Format**: The BOF uses NT path format (`\??\C:\...`) for the process name. This is the native format used by `NtCreateUserProcess` and bypasses some Win32 path parsing mechanisms.

## Shellcode Execution Methods

### 1. Direct RIP Hijacking
```
Original State:          Modified State:
┌──────────────┐        ┌──────────────┐
│ RIP: ntdll   │   →    │ RIP: 0x7FFE  │ (shellcode)
│ RAX: ...     │        │ RAX: ...     │
└──────────────┘        └──────────────┘
```
**Advantage**: Simple and reliable.  
**Detection Risk**: High - RIP directly pointing to non-module memory is easily detected by EDR thread scanning.

### 2. JMP RAX Gadget
```
Step 1: Find Gadget               Step 2: Set Context
┌──────────────────┐             ┌──────────────────┐
│ Scan ntdll.dll   │             │ RIP: ntdll!gadget│ (0xFF 0xE0)
│ for 0xFF 0xE0    │    →        │ RAX: shellcode   │
└──────────────────┘             └──────────────────┘
```
**Advantage**: RIP points to legitimate ntdll.dll, more stealthy than direct hijacking.  
**Detection Risk**: Medium - Suspicious RAX value and unusual gadget execution may trigger heuristics.

### 3. JMP RBX Gadget
```
Step 1: Find Gadget               Step 2: Set Context
┌──────────────────┐             ┌──────────────────┐
│ Scan ntdll.dll   │             │ RIP: ntdll!gadget│ (0xFF 0xE3)
│ for 0xFF 0xE3    │    →        │ RBX: shellcode   │
└──────────────────┘             └──────────────────┘
```
**Advantage**: Similar to JMP RAX, RIP remains in legitimate module space.  
**Detection Risk**: Medium - Same as JMP RAX, slightly different register makes detection signatures less common.

### 4. Callback Function Hijacking
```
EnumResourceTypesW(hModule, lpEnumFunc, lParam)
                              ↓
                    RCX = NULL
                    RDX = shellcode address
                    R8  = NULL
```
**Advantage**: Leverages legitimate callback mechanism, appears as normal Windows API usage.  
**Detection Risk**: Low-Medium - Requires CFG disabled. NULL module handle and callback validation may trigger alerts.

## Mitigation Policies: Benefits and Risks

### Disable CFG (Control Flow Guard)
**Purpose**: Required for callback function execution method. CFG validates indirect call targets and would block shellcode execution.  
**Risk**: Disabling CFG is a strong indicator of malicious intent. Very few legitimate applications disable CFG during process creation.  
**Recommendation**: Only enable when using callback execution method.

### Block DLL Policy
**Purpose**: Prevents loading of non-Microsoft-signed DLLs, blocking security product hooks and monitoring DLLs from being injected.  
**Risk**: Unusual mitigation policy for typical processes. May trigger EDR alerts on process creation with this attribute.  
**Recommendation**: Use selectively - effective against DLL-based EDR hooks but creates detection artifact.

### RWX Memory Allocation
**Purpose**: Simplifies injection by allocating memory with Read-Write-Execute permissions directly.  
**Risk**: RWX memory is a critical indicator for memory scanners. 
**Recommendation**: Use RW→RX transition instead (default). Allocate as RW, write shellcode, then change to RX.

## Detection Vectors

### ETW-TI (Threat Intelligence) Callbacks

**NtGetContextThread / NtSetContextThread**:
- ETW-TI provides callbacks for thread context manipulation via `EtwTiLogReadWriteVm`
- Modifying RIP register on suspended threads is a strong injection indicator
- Detection: Context modifications are logged with thread ID, process ID, and modified registers

### Kernel Callbacks

**Process Creation (PsSetCreateProcessNotifyRoutine)**:
- `NtCreateUserProcess` triggers kernel callbacks visible to EDR drivers
- Suspended process creation followed by cross-process operations is suspicious
- Detection: Process creation with unusual parent (PPID spoofing), mitigation policies (BlockDLL, CFG disabled)

**Memory Allocation**:
- RWX memory allocations are monitored at kernel level via process callbacks
- Even without ETW-TI, kernel drivers can detect RWX via `MmProtectMdlSystemAddress` events
- Detection: Unbacked executable memory (not mapped from disk file)

## Evasion Techniques

| Technique | Bypasses |
|-----------|----------|
| **Indirect Syscalls** | Userland API hooks (EDR/AV) |
| **Draugr Stack Spoofing** | Call stack inspection tools |
| **PPID Spoofing** | Process tree analysis |
| **Gadget-based Execution** | Direct RIP detection |

## Usage

### Load Script
```
Cobalt Strike → Script Manager → Load → BOF_spawn.cna
```

### Configure
```
Menu: Additionals postex → Spawn Process Config
```

### Execute
```
beacon> spawn_beacon <listener_name>
beacon> spawn_shellcode /path/to/payload.bin
```

## Compilation

With Dockerfile:

```bash
sudo docker build -t ubuntu-gcc-13 .
sudo docker run --rm -it -v "$PWD":/work -w /work ubuntu-gcc-13:latest make
 ```

Or, if you have nasm, make, and mingw-w64 (compatible with gcc-14) on your system
```
make
```

Output: `Bin/bof.o`

## Limitations

- **CET (Control-flow Enforcement Technology)**: Synthetic stack frames may trigger violations in CET-enabled processes
- **Architecture**: x64 only - no x86 support
- **Kernel Visibility**: Process creation still visible to kernel callbacks despite userland evasion

## Credit

- **RastaMouse** : https://offensivedefence.co.uk/authors/rastamouse/
- **Capt. Meelo**: https://captmeelo.com/redteam/maldev/2022/05/10/ntcreateuserprocess.html
- **Sektor7**: https://institute.sektor7.net/view/courses/rto-win-evasion
