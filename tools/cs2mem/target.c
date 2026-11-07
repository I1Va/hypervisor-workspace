#include "target.h"
#include "hvmem.h"
#include "hvcalls.h"

#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * The hypervisor can read any address space, but it needs that space's CR3.
 * HYPERCALL_GET_CURRENT_CR3 returns only the *caller's* CR3, which is correct
 * for reading our own process and useless for reading the game.
 *
 * HYPERCALL_GET_PROCESS_CR3 is the addition this tool expects; see
 * hypervisor_patch.md. It is a hypercall rather than a kernel driver because the
 * hypervisor is already in root mode and can walk PsActiveProcessHead in guest
 * physical memory without any of the driver-loading ceremony.
 *
 * If the hypervisor predates the patch the call returns HypercallErrInvalidNum,
 * which is reported as exactly that - not as "game not found".
 */
#define HYPERCALL_GET_PROCESS_CR3 0x2C41D7E9A05B3ULL

static uint64_t hv_get_process_cr3(uint32_t pid)
{
	uint64_t ret;
	register uint64_t rax __asm__("rax") = HYPERCALL_CPUID_LEAF;
	register uint64_t rcx __asm__("rcx") = HYPERCALL_KEY;
	register uint64_t rdi __asm__("rdi") = HYPERCALL_GET_PROCESS_CR3;
	register uint64_t rsi __asm__("rsi") = pid;
	register uint64_t rdx __asm__("rdx") = 0;
	register uint64_t r8  __asm__("r8")  = 0;
	register uint64_t r9  __asm__("r9")  = 0;
	__asm__ __volatile__("cpuid"
			     : "=a"(rax)
			     : "a"(rax), "c"(rcx), "D"(rdi), "S"(rsi),
			       "d"(rdx), "r"(r8), "r"(r9)
			     : "rbx", "memory");
	ret = rax;
	return ret;
}

int target_resolve_cr3(DWORD pid, uint64_t *cr3, char *err, size_t err_cap)
{
	uint64_t got = hv_get_process_cr3(pid);

	if (got == 0) {
		snprintf(err, err_cap,
			 "the hypervisor does not expose HYPERCALL_GET_PROCESS_CR3 "
			 "(see hypervisor_patch.md), or PID %lu has no CR3",
			 (unsigned long)pid);
		return 1;
	}
	/* The hypercall returns the CR3 value itself, not a status. */
	*cr3 = got;
	return 0;
}

int target_open(target *t, const wchar_t *exe_name, char *err, size_t err_cap)
{
	HANDLE snap;
	PROCESSENTRY32W pe;
	module_info *cur;

	memset(t, 0, sizeof(*t));

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		snprintf(err, err_cap, "CreateToolhelp32Snapshot failed (%lu)",
			 (unsigned long)GetLastError());
		return 1;
	}

	pe.dwSize = sizeof(pe);
	if (!Process32FirstW(snap, &pe)) {
		CloseHandle(snap);
		snprintf(err, err_cap, "Process32First failed");
		return 1;
	}
	do {
		if (_wcsicmp(pe.szExeFile, exe_name) == 0) {
			t->pid = pe.th32ProcessID;
			break;
		}
	} while (Process32NextW(snap, &pe));
	CloseHandle(snap);

	if (t->pid == 0) {
		snprintf(err, err_cap, "process %ls is not running", exe_name);
		return 1;
	}

	/*
	 * PROCESS_QUERY_LIMITED_INFORMATION is enough for module enumeration and
	 * does not require SeDebugPrivilege. We deliberately do not request
	 * VM_READ: the whole point is that reads go through the hypervisor, so the
	 * tool never needs the handle to be readable. That also means a mistake in
	 * the hypervisor path cannot silently fall back to a plain read.
	 */
	t->process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, t->pid);
	if (t->process == NULL) {
		snprintf(err, err_cap, "OpenProcess(%lu) failed (%lu)",
			 (unsigned long)t->pid, (unsigned long)GetLastError());
		return 1;
	}

	if (target_resolve_cr3(t->pid, &t->cr3, err, err_cap) != 0) {
		CloseHandle(t->process);
		t->process = NULL;
		return 1;
	}

	/* Modules: base addresses for the code we already reversed. */
	snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, t->pid);
	if (snap == INVALID_HANDLE_VALUE) {
		snprintf(err, err_cap, "module snapshot failed (%lu)",
			 (unsigned long)GetLastError());
		CloseHandle(t->process);
		t->process = NULL;
		return 1;
	}

	{
		MODULEENTRY32W me;
		me.dwSize = sizeof(me);
		cur = t->modules;
		if (Module32FirstW(snap, &me)) {
			do {
				if (t->module_count >= (int)(sizeof(t->modules) / sizeof(t->modules[0])))
					break;
				cur->base = (uint64_t)(uintptr_t)me.modBaseAddr;
				cur->size = me.modBaseSize;
				WideCharToMultiByte(CP_ACP, 0, me.szModule, -1,
						    cur->name, MAX_PATH, NULL, NULL);
				cur++;
				t->module_count++;
			} while (Module32NextW(snap, &me));
		}
	}
	CloseHandle(snap);

	return 0;
}

void target_close(target *t)
{
	if (t->process != NULL) {
		CloseHandle(t->process);
		t->process = NULL;
	}
}

const module_info *target_module(const target *t, const char *name)
{
	size_t want = strlen(name);
	size_t want_base = want;

	/* Accept "client" or "client.dll". */
	if (want > 4 && _stricmp(name + want - 4, ".dll") == 0)
		want_base = want - 4;

	for (int i = 0; i < t->module_count; i++) {
		const char *n = t->modules[i].name;
		size_t len = strlen(n);

		if (len > 4 && _stricmp(n + len - 4, ".dll") == 0)
			len -= 4;
		if (len == want_base && _strnicmp(n, name, want_base) == 0)
			return &t->modules[i];
	}
	return NULL;
}

/*
 * NtQueryInformationProcess(ProcessCommandLineInformation) = class 60.
 * Declared locally rather than pulling in winternl.h, which is large and
 * historically inconsistent about this class.
 */
typedef LONG (NTAPI *NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} unicode_string_local;

int target_command_line(const target *t, char *out, size_t cap)
{
	typedef LONG (NTAPI *fn_t)(HANDLE, int, void *, unsigned long, unsigned long *);
	static fn_t ntqip = NULL;
	unicode_string_local us;
	unsigned long need = 0;
	HMODULE ntdll;
	char *buf;

	if (cap == 0)
		return 1;
	out[0] = '\0';

	if (ntqip == NULL) {
		ntdll = GetModuleHandleA("ntdll.dll");
		if (ntdll == NULL)
			return 1;
		ntqip = (fn_t)(void *)GetProcAddress(ntdll, "NtQueryInformationProcess");
		if (ntqip == NULL)
			return 1;
	}

	memset(&us, 0, sizeof(us));

	/* Class 60 = ProcessCommandLineInformation. First call sizes it. */
	if (ntqip(t->process, 60, &us, sizeof(us), &need) != 0)
		return 1;
	if (need == 0)
		return 1;

	buf = (char *)malloc(need);
	if (buf == NULL)
		return 1;

	if (ntqip(t->process, 60, buf, need, &need) != 0) {
		free(buf);
		return 1;
	}

	{
		unicode_string_local *p = (unicode_string_local *)buf;
		WideCharToMultiByte(CP_ACP, 0, p->Buffer, p->Length / sizeof(WCHAR),
				    out, (int)cap - 1, NULL, NULL);
		out[cap - 1] = '\0';
	}
	free(buf);
	return 0;
}
