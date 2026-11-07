/*
 * hvmem.h - read a guest address space through the hypervisor.
 *
 * Why this exists as a separate layer: every game-data read is "translate a VA
 * in some process's CR3, copy N bytes out". Getting that wrong is not a visible
 * error, it is plausible garbage (a stale CR3 returns another process's memory,
 * and a short read returns a struct with a valid-looking header and zeroed
 * tail). So the primitives here are deliberately loud: every read is checked
 * against the page it crossed, and a failure names which page failed.
 *
 * Offline use only. This reads the address space of a process you launched
 * yourself, on a machine you control, with the hypervisor you built.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct hv_ctx
{
	uint64_t cr3;      /* address space to read: the game's, not ours */
	int      ok;       /* set once hv_ctx_init has validated a hypercall */
	uint64_t faults;   /* pages that failed to translate */
} hv_ctx;

/* Prove the hypercall path works and capture the current CR3. Returns 0 on success. */
int hv_ctx_init(hv_ctx *ctx);

/* Switch to another address space (a different process, or a new CR3 after a restart). */
void hv_ctx_use(hv_ctx *ctx, uint64_t cr3);

/*
 * Copy `size` bytes from guest VA `addr` into `out`.
 *
 * Reads page by page, because the hypercall's own virtual copy assumes the
 * destination is contiguous (it is: our buffer) but the *source* pages are
 * arbitrary physical pages. A single large call would work, but splitting it
 * makes a partial failure report which page died instead of silently returning
 * a buffer that is half stale.
 *
 * Returns 0 on success, non-zero on the first page that failed.
 */
int hv_read(hv_ctx *ctx, uint64_t addr, void *out, size_t size);

/* Typed helpers. */
static inline int hv_read_u64(hv_ctx *ctx, uint64_t addr, uint64_t *out)
{
	return hv_read(ctx, addr, out, sizeof(*out));
}

static inline int hv_read_u32(hv_ctx *ctx, uint64_t addr, uint32_t *out)
{
	return hv_read(ctx, addr, out, sizeof(*out));
}

static inline int hv_read_u16(hv_ctx *ctx, uint64_t addr, uint16_t *out)
{
	return hv_read(ctx, addr, out, sizeof(*out));
}

static inline int hv_read_u8(hv_ctx *ctx, uint64_t addr, uint8_t *out)
{
	return hv_read(ctx, addr, out, sizeof(*out));
}

static inline int hv_read_f32(hv_ctx *ctx, uint64_t addr, float *out)
{
	return hv_read(ctx, addr, out, sizeof(*out));
}

/*
 * Read a NUL-terminated string of at most `cap-1` bytes. Returns 0 on success.
 * Reads in chunks and stops at the first NUL; a string that is not terminated
 * within `cap` is reported as an error rather than silently truncated, because
 * a truncated class name is worse than no name.
 */
int hv_read_cstr(hv_ctx *ctx, uint64_t addr, char *out, size_t cap);
