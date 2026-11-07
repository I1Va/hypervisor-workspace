#include "hvmem.h"
#include "hvcalls.h"

#include <string.h>

#define PAGE 0x1000ULL

int hv_ctx_init(hv_ctx *ctx)
{
	uint64_t cr3 = 0;

	memset(ctx, 0, sizeof(*ctx));

	/*
	 * A wrong hypercall key returns HypercallErrInvalidKey and, importantly,
	 * still executes a CPUID - so it is indistinguishable from success unless
	 * the return value is checked. That is exactly how a stale tool silently
	 * reads nothing for an hour.
	 */
	if (hv_get_cr3(&cr3) != HV_OK || cr3 == 0)
		return 1;

	ctx->cr3 = cr3;
	ctx->ok = 1;
	return 0;
}

void hv_ctx_use(hv_ctx *ctx, uint64_t cr3)
{
	ctx->cr3 = cr3;
}

int hv_read(hv_ctx *ctx, uint64_t addr, void *out, size_t size)
{
	uint8_t *dst = (uint8_t *)out;

	if (!ctx->ok)
		return 2;
	if (size == 0)
		return 0;

	while (size > 0) {
		uint64_t page_off = addr & (PAGE - 1);
		size_t chunk = (size_t)(PAGE - page_off);

		if (chunk > size)
			chunk = size;

		/*
		 * Touch the destination first. The hypervisor writes it with a
		 * physical store after translating our CR3; if the page is not
		 * resident yet the store lands somewhere else or faults in the VMM.
		 */
		dst[0] = 0;
		dst[chunk - 1] = 0;

		if (hv_read_virtual(dst, addr, chunk, ctx->cr3) != HV_OK) {
			ctx->faults++;
			return 3;
		}

		addr += chunk;
		dst += chunk;
		size -= chunk;
	}
	return 0;
}

int hv_read_cstr(hv_ctx *ctx, uint64_t addr, char *out, size_t cap)
{
	size_t filled = 0;

	if (cap == 0)
		return 1;

	while (filled < cap) {
		uint64_t page_off = addr & (PAGE - 1);
		size_t chunk = (size_t)(PAGE - page_off);
		size_t room = cap - filled;
		uint8_t *nul;

		if (chunk > room)
			chunk = room;

		if (hv_read(ctx, addr, out + filled, chunk) != 0)
			return 2;

		nul = (uint8_t *)memchr(out + filled, 0, chunk);
		if (nul != NULL)
			return 0;

		addr += chunk;
		filled += chunk;
	}

	/* No terminator within cap: refuse rather than truncate. */
	return 3;
}
