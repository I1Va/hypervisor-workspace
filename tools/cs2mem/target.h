/*
 * target.h - locate the game process and its modules from inside the guest.
 *
 * The hypervisor can read any address space, but it needs a CR3 and a module
 * base. This layer gets both by asking Windows rather than by guessing:
 * Toolhelp32 gives us the process, its PID, and each module's base. The CR3 for
 * that PID is then read out of the kernel's own structures.
 *
 * Only the *guest's own* Windows API is used here - no kernel driver, no
 * undocumented syscall. That keeps the tool buildable and reviewable, and it is
 * sufficient because we are not trying to hide: we run as admin on our own
 * machine, in an offline session.
 */
#pragma once

#include <stdint.h>
#include <windows.h>

typedef struct module_info
{
	uint64_t base;      /* preferred/actual load address */
	uint32_t size;
	char     name[MAX_PATH];
} module_info;

typedef struct target
{
	DWORD        pid;
	HANDLE       process;
	uint64_t     cr3;       /* kernel EPROCESS->DirectoryTableBase */
	module_info  modules[64];
	int          module_count;
} target;

/*
 * Open the process by name and resolve its CR3.
 *
 * Returns 0 on success. On failure, `err` receives a human-readable reason -
 * "game not running" and "cannot read kernel memory" are different problems and
 * must not both print as a generic failure.
 */
int target_open(target *t, const wchar_t *exe_name, char *err, size_t err_cap);

void target_close(target *t);

/* Find a loaded module by name (case-insensitive, "client.dll" or "client"). */
const module_info *target_module(const target *t, const char *name);

/*
 * Read the target's command line.
 *
 * Uses NtQueryInformationProcess(ProcessCommandLineInformation), which needs
 * only PROCESS_QUERY_LIMITED_INFORMATION - the same access we already hold - so
 * this does not add a read handle. Returns 0 on success.
 *
 * Used to enforce the offline guard: the tool refuses to run unless the game was
 * started with -insecure, which is what turns VAC off for a local bot match.
 */
int target_command_line(const target *t, char *out, size_t cap);

/*
 * Resolve the CR3 of a process from its EPROCESS.
 *
 * This is the one genuinely privileged step. It walks the kernel's PsActiveProcess
 * list to find the EPROCESS whose UniqueProcessId matches, then reads
 * DirectoryTableBase. Requires SeDebugPrivilege.
 *
 * Kept in its own function because it is the part most likely to break across
 * Windows builds, and because it is the only place that touches kernel memory.
 */
int target_resolve_cr3(DWORD pid, uint64_t *cr3, char *err, size_t err_cap);
