/*
 * selftest.c - prove the discovery algorithm against a synthetic address space.
 *
 * This exists because `discover` is the piece most likely to be wrong, and
 * testing it against a real game requires a real game. A synthetic image built
 * to the layout the algorithm expects proves the algorithm; the only thing left
 * untested is whether the real layout matches the assumptions.
 *
 * What is modelled:
 *   - a module image with a data section
 *   - a global pointer (dw_entity_system) at a known RVA
 *   - a CGameEntitySystem with a chunk-table pointer and highest-index field
 *   - two chunks of 512 slots, with live players at known indices
 *   - both chunk layouts: by-value, and via-identity
 *
 * Ground truth is chosen to be *not* the first candidate in every list, so a
 * test that passes proves the search works rather than that the defaults
 * happened to be right.
 *
 * Build and run on the host (not the guest):
 *   cc -O2 -I. -o selftest selftest.c discover.c hvmem.c cs2cfg.c -lm
 *   ./selftest
 */
#include "cs2cfg.h"
#include "discover.h"
#include "hvmem.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Layout of the synthetic world. Deliberately awkward numbers. */
/*
 * The synthetic address space covers the whole "world", not just the module
 * image: entity systems and chunks live at their own addresses outside
 * client.dll's image. Modelling them inside the image would make the test pass
 * for the wrong reason.
 *
 * Addresses are chosen small and packed so the test allocates 32 MB, not 400.
 */
#define WORLD_BASE      0x01000000ULL
#define WORLD_SIZE      0x02000000ULL   /* 32 MB */

#define IMAGE_BASE      0x01000000ULL
#define IMAGE_SIZE      0x00400000ULL   /* 4 MB module image */
#define IMAGE_SIZE      0x00400000ULL
#define DATA_RVA        0x00200000
#define DATA_SIZE       0x00100000

/* The global pointer lives at this RVA inside .data. */
#define DW_ENTITY_RVA   (DATA_RVA + 0x1230)

/* Entity-system object, at an address that is not page aligned. */
#define ES_ADDR         0x01800000ULL
#define ES_LIST_OFF     0x10
#define ES_HIGHEST_OFF  0x18

/* Chunks. */
#define CHUNK0          0x01880000ULL
#define CHUNK1          0x018A0000ULL

/* Ground truth, chosen off-default. */
#define TRUE_STRIDE     0x88
#define TRUE_HEALTH     0x338
#define TRUE_TEAM       0x3eb
#define TRUE_ORIGIN     0x1320
#define TRUE_IDENTITY   0x48

/* Number of live players to place, and which indices they occupy. */
#define PLAYER_COUNT    6
static const int player_indices[PLAYER_COUNT] = { 3, 7, 11, 40, 100, 505 };

static void put_u64(uint8_t *base, uint64_t addr, uint64_t v)
{
	memcpy(base + (addr - IMAGE_BASE), &v, 8);
}

static void put_u32(uint8_t *base, uint64_t addr, uint32_t v)
{
	memcpy(base + (addr - IMAGE_BASE), &v, 4);
}

static void put_u8(uint8_t *base, uint64_t addr, uint8_t v)
{
	base[addr - IMAGE_BASE] = v;
}

static void put_f32(uint8_t *base, uint64_t addr, float v)
{
	memcpy(base + (addr - IMAGE_BASE), &v, 4);
}

/*
 * Build the synthetic image. `via_identity` selects the chunk layout.
 * Returns the buffer, which the caller owns.
 */
static uint8_t *build(int via_identity)
{
	uint8_t *img = calloc(1, WORLD_SIZE);

	if (img == NULL)
		return NULL;

	/* The global: dw_entity_system points at the entity-system object. */
	put_u64(img, IMAGE_BASE + DW_ENTITY_RVA, ES_ADDR);

	/* The entity system. */
	put_u64(img, ES_ADDR + ES_LIST_OFF, ES_ADDR + 0x800);  /* chunk table */
	put_u32(img, ES_ADDR + ES_HIGHEST_OFF, 600);

	/* Chunk table: two chunks. */
	put_u64(img, ES_ADDR + 0x800, CHUNK0);
	put_u64(img, ES_ADDR + 0x808, CHUNK1);

	/* Players. */
	for (int i = 0; i < PLAYER_COUNT; i++) {
		int idx = player_indices[i];
		uint64_t chunk = (idx / 512) ? CHUNK1 : CHUNK0;
		uint64_t slot = chunk + (uint64_t)(idx % 512) * TRUE_STRIDE;
		uint64_t ent = slot;

		if (via_identity) {
			/* The identity holds a pointer to the entity elsewhere. */
			uint64_t identity_addr = slot;
			uint64_t entity_addr = 0x01A00000ULL + (uint64_t)i * 0x1000;

			put_u64(img, identity_addr + TRUE_IDENTITY, entity_addr);
			ent = entity_addr;
		}

		put_u32(img, ent + TRUE_HEALTH, 100 - i * 7);
		put_u8(img, ent + TRUE_TEAM, (i % 2) ? 3 : 2);
		put_f32(img, ent + TRUE_ORIGIN + 0, 1000.0f + (float)i * 13.5f);
		put_f32(img, ent + TRUE_ORIGIN + 4, -500.0f + (float)i * 7.25f);
		put_f32(img, ent + TRUE_ORIGIN + 8, 64.0f);
	}

	/* Decoys: entities that must NOT validate. */
	for (int i = 0; i < 20; i++) {
		uint64_t slot = CHUNK0 + (uint64_t)(200 + i) * TRUE_STRIDE;
		put_u32(img, slot + TRUE_HEALTH, 0);            /* dead */
		put_u8(img, slot + TRUE_TEAM, 0);               /* no team */
		put_f32(img, slot + TRUE_ORIGIN, 0.0f);         /* zero origin */
		put_f32(img, slot + TRUE_ORIGIN + 4, 0.0f);
		put_f32(img, slot + TRUE_ORIGIN + 8, 0.0f);
	}

	return img;
}

static int run_case(int via_identity, const char *label)
{
	uint8_t *img = build(via_identity);
	struct synth *s;
	hv_ctx mem;
	discover_opts o;
	discover_result r;
	cs2_offsets off;
	int rc;
	int failures = 0;

	if (img == NULL) {
		printf("%s: cannot allocate image\n", label);
		return 1;
	}

	s = synth_create(WORLD_BASE, WORLD_SIZE);
	if (s == NULL) {
		free(img);
		printf("%s: cannot create synth\n", label);
		return 1;
	}
	memcpy(synth_ptr(s, WORLD_BASE, WORLD_SIZE), img, WORLD_SIZE);

	memset(&mem, 0, sizeof(mem));
	synth_use(&mem, s);

	memset(&o, 0, sizeof(o));
	o.client_base = IMAGE_BASE;
	o.client_size = IMAGE_SIZE;
	o.data_rva = DATA_RVA;
	o.data_size = DATA_SIZE;

	printf("=== %s\n", label);

	rc = discover_entity_system(&mem, &o, &r);
	if (rc != 0) {
		printf("  FAIL: entity system not found: %s\n", r.note);
		failures++;
	} else {
		printf("  entity system 0x%llx (expect 0x%llx) %s\n",
		       (unsigned long long)r.entity_system,
		       (unsigned long long)ES_ADDR,
		       r.entity_system == ES_ADDR ? "ok" : "MISMATCH");
		if (r.entity_system != ES_ADDR)
			failures++;
		if (r.highest_index != 600) {
			printf("  FAIL: highest index %u, expect 600\n", r.highest_index);
			failures++;
		}
	}

	rc = discover_layout(&mem, &o, &r);
	if (rc != 0) {
		printf("  FAIL: layout not determined: %s\n", r.note);
		failures++;
	} else {
		printf("  stride 0x%x (expect 0x%x) %s\n", r.chunk_stride, TRUE_STRIDE,
		       r.chunk_stride == TRUE_STRIDE ? "ok" : "MISMATCH");
		printf("  health 0x%x (expect 0x%x) %s\n", r.off_health, TRUE_HEALTH,
		       r.off_health == TRUE_HEALTH ? "ok" : "MISMATCH");
		printf("  team   0x%x (expect 0x%x) %s\n", r.off_team, TRUE_TEAM,
		       r.off_team == TRUE_TEAM ? "ok" : "MISMATCH");
		printf("  origin 0x%x (expect 0x%x) %s\n", r.off_origin, TRUE_ORIGIN,
		       r.off_origin == TRUE_ORIGIN ? "ok" : "MISMATCH");
		printf("  identity %s (expect %s) %s\n",
		       r.off_identity_entity ? "via-identity" : "by-value",
		       via_identity ? "via-identity" : "by-value",
		       (!!r.off_identity_entity) == via_identity ? "ok" : "MISMATCH");
		printf("  validated %d entities\n", r.stride_validated);

		if (r.chunk_stride != TRUE_STRIDE)
			failures++;
		if (r.off_health != TRUE_HEALTH)
			failures++;
		if (r.off_team != TRUE_TEAM)
			failures++;
		if (r.off_origin != TRUE_ORIGIN)
			failures++;
		if ((!!r.off_identity_entity) != via_identity)
			failures++;
	}

	memset(&off, 0, sizeof(off));
	if (discover_all(&mem, &o, &off, &r) == 0) {
		printf("  dw_entity_system 0x%llx (expect 0x%llx) %s\n",
		       (unsigned long long)off.dw_entity_system,
		       (unsigned long long)(DW_ENTITY_RVA),
		       off.dw_entity_system == DW_ENTITY_RVA ? "ok" : "MISMATCH");
		if (off.dw_entity_system != DW_ENTITY_RVA)
			failures++;
	}

	synth_destroy(s);
	free(img);

	printf("  -> %s\n\n", failures == 0 ? "PASS" : "FAIL");
	return failures;
}

/* A world with no players must be reported as such, not guessed. */
static int run_empty_case(void)
{
	struct synth *s = synth_create(WORLD_BASE, WORLD_SIZE);
	hv_ctx mem;
	discover_opts o;
	discover_result r;
	int failures = 0;

	if (s == NULL)
		return 1;

	memset(&mem, 0, sizeof(mem));
	synth_use(&mem, s);

	memset(&o, 0, sizeof(o));
	o.client_base = IMAGE_BASE;
	o.client_size = IMAGE_SIZE;
	o.data_rva = DATA_RVA;
	o.data_size = DATA_SIZE;

	printf("=== empty world (no players)\n");
	if (discover_entity_system(&mem, &o, &r) == 0) {
		printf("  FAIL: found an entity system in an empty image\n");
		failures++;
	} else {
		printf("  correctly found nothing: %s\n", r.note);
	}
	printf("  -> %s\n\n", failures == 0 ? "PASS" : "FAIL");
	synth_destroy(s);
	return failures;
}

int main(void)
{
	int failures = 0;

	failures += run_case(0, "by-value chunk layout");
	failures += run_case(1, "via-identity chunk layout");
	failures += run_empty_case();

	printf("%s: %d failure(s)\n", failures == 0 ? "ALL PASS" : "FAILURES", failures);
	return failures == 0 ? 0 : 1;
}
