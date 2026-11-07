/*
 * hvcalls.h - guest-side hypercall ABI, self-contained.
 *
 * Mirrors Sources/Hypercall/Hypercall.h from the hypervisor, but written so a
 * standalone Windows tool can include it without the EFI build tree. Keep the
 * constants in sync: a mismatch is not a compile error, it is a hypercall that
 * silently does nothing and returns garbage.
 *
 * ABI (from VmxExitHandlers.c, the CPUID path):
 *   EAX = 0x4000BABE, RCX = HYPERCALL_KEY, RDI = call number,
 *   RSI = arg1, RDX = arg2, R8 = arg3, R9 = arg4.
 *   Result in RAX.
 *
 * RCX holds the key and so cannot be an argument, which is why the call number
 * lives in RDI and arguments start at RSI.
 */
#pragma once

#include <stdint.h>

#define HYPERCALL_KEY        0xBABEB8CEC88D3ULL
#define HYPERCALL_CPUID_LEAF 0x4000BABE

#define HYPERCALL_READ_PHYSICAL_MEMORY             0x392C94DF883DAULL
#define HYPERCALL_WRITE_PHYSICAL_MEMORY            0x3FC3B9BA157BEULL
#define HYPERCALL_GET_CURRENT_CR3                  0x2349923a6e1d6ULL
#define HYPERCALL_READ_VIRTUAL_MEMORY              0x3FCDA06108008ULL
#define HYPERCALL_WRITE_VIRTUAL_MEMORY             0x1BC71CA548EC6ULL
#define HYPERCALL_GET_PHYSICAL_ADDRESS_FROM_VIRTUAL 0x2A027EB505336ULL
#define HYPERCALL_GET_STATS                        0x3d5b8a17c204fULL

/*
 * ReadVirtualMemory(gva_dest, gva2_src, sz, dst_cr3)
 *
 * src is a guest virtual address in the address space identified by dst_cr3.
 * dest is a virtual address in the *current* address space. Returns 0 on
 * success (HypercallOk).
 *
 * The destination must be resident and writable: the hypervisor writes it with
 * WritePhysicalMem after translating the current CR3, so a page that is paged
 * out or read-only makes the copy land in the wrong place or fault inside the
 * VMM. Tools therefore pass a buffer they have just touched.
 */
static inline uint64_t hv_read_virtual(void *dest, uint64_t src, uint64_t size, uint64_t target_cr3)
{
	uint64_t ret;
	register uint64_t rax __asm__("rax") = HYPERCALL_CPUID_LEAF;
	register uint64_t rcx __asm__("rcx") = HYPERCALL_KEY;
	register uint64_t rdi __asm__("rdi") = HYPERCALL_READ_VIRTUAL_MEMORY;
	register uint64_t rsi __asm__("rsi") = (uint64_t)dest;
	register uint64_t rdx __asm__("rdx") = src;
	register uint64_t r8  __asm__("r8")  = size;
	register uint64_t r9  __asm__("r9")  = target_cr3;
	__asm__ __volatile__("cpuid"
			     : "=a"(rax)
			     : "a"(rax), "c"(rcx), "D"(rdi), "S"(rsi),
			       "d"(rdx), "r"(r8), "r"(r9)
			     : "rbx", "memory");
	ret = rax;
	return ret;
}

/* Translate a guest VA to a GPA in the address space identified by cr3. */
static inline uint64_t hv_translate(uint64_t cr3, uint64_t vaddr, uint64_t *out_pa)
{
	uint64_t ret;
	register uint64_t rax __asm__("rax") = HYPERCALL_CPUID_LEAF;
	register uint64_t rcx __asm__("rcx") = HYPERCALL_KEY;
	register uint64_t rdi __asm__("rdi") = HYPERCALL_GET_PHYSICAL_ADDRESS_FROM_VIRTUAL;
	register uint64_t rsi __asm__("rsi") = cr3;
	register uint64_t rdx __asm__("rdx") = vaddr;
	register uint64_t r8  __asm__("r8")  = (uint64_t)out_pa;
	register uint64_t r9  __asm__("r9")  = 0;
	__asm__ __volatile__("cpuid"
			     : "=a"(rax)
			     : "a"(rax), "c"(rcx), "D"(rdi), "S"(rsi),
			       "d"(rdx), "r"(r8), "r"(r9)
			     : "rbx", "memory");
	ret = rax;
	return ret;
}

/* Fill *cr3 with the hypervisor's current guest CR3. */
static inline uint64_t hv_get_cr3(uint64_t *cr3)
{
	uint64_t ret;
	register uint64_t rax __asm__("rax") = HYPERCALL_CPUID_LEAF;
	register uint64_t rcx __asm__("rcx") = HYPERCALL_KEY;
	register uint64_t rdi __asm__("rdi") = HYPERCALL_GET_CURRENT_CR3;
	register uint64_t rsi __asm__("rsi") = (uint64_t)cr3;
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

#define HV_OK 0
