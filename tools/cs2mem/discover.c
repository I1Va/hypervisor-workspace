#include "discover.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

/* Entity chunks in CS2 hold 512 slots; this is stable across builds and is used
 * only as a starting hypothesis, then confirmed by validation. */
#define DEFAULT_CHUNK_ENTITIES 512

/* How far into an entity to scan for fields. A pawn's members sit well inside
 * this; going further costs time and finds unrelated data. */
#define FIELD_SCAN_LIMIT 0x2000

static int finite_vec3(const float v[3])
{
	return isfinite(v[0]) && isfinite(v[1]) && isfinite(v[2]);
}

/*
 * A player origin has a structural property that a shifted read does not:
 * z is the vertical axis and a standing player is above the world floor, so z
 * is positive. Reading a vec3 one float early puts y into the z slot, and y is
 * routinely negative.
 *
 * This is what makes the offset discoverable rather than guessed. Without it a
 * vec3 validates equally at off-4, off and off+4, and any tie-break is arbitrary.
 */
static int origin_sane(const float v[3])
{
	if (!finite_vec3(v))
		return 0;
	if (fabsf(v[0]) > 32768.0f || fabsf(v[1]) > 32768.0f || fabsf(v[2]) > 32768.0f)
		return 0;
	if (v[0] == 0.0f && v[1] == 0.0f && v[2] == 0.0f)
		return 0;
	/* z is height above the world floor: players are above it, not below. */
	if (v[2] <= 0.0f || v[2] > 8192.0f)
		return 0;
	return 1;
}

/*
 * Stage 1: find the entity system.
 *
 * The data section of client.dll holds a global pointer. A pointer is only
 * accepted if its target plausibly *is* an entity system, which is tested by
 * reading three things that must be mutually consistent:
 *
 *   +off_entity_list    a non-null pointer
 *   +off_highest_index  a small positive count
 *   chunk_table[0]      a readable chunk pointer
 *
 * The offsets used here are not yet known, so the scan tries the small set of
 * layouts that the entity-system structure could have. This is the part most
 * likely to need adjustment when the real structure is measured.
 */
int discover_entity_system(hv_ctx *mem, const discover_opts *o, discover_result *r)
{
	uint64_t addr;
	uint64_t end = o->client_base + o->data_rva + o->data_size;
	int tried = 0;

	memset(r, 0, sizeof(*r));

	/*
	 * Candidate offsets within CGameEntitySystem for the chunk-table pointer
	 * and the highest index. These are hypotheses; each is validated by the
	 * consistency test below rather than assumed.
	 *
	 * Constraint that rules out most pairs: the chunk-table pointer is 8 bytes,
	 * so the highest-index field must be at least 8 bytes away from it. A pair
	 * like {0x10, 0x14} overlaps and can never be right - writing a small
	 * count there would corrupt the pointer's upper half.
	 */
	static const struct { uint32_t list, highest; } layouts[] = {
		{ 0x10, 0x18 },
		{ 0x10, 0x1c },
		{ 0x08, 0x10 },
		{ 0x18, 0x20 },
		{ 0x20, 0x28 },
	};

	addr = o->client_base + o->data_rva;

	for (; addr + 8 <= end; addr += 8) {
		uint64_t target = 0;

		if (hv_read_u64(mem, addr, &target) != 0)
			continue;
		if (target < 0x10000 || target > 0x7fffffffffffULL)
			continue;

		tried++;

		for (size_t l = 0; l < sizeof(layouts) / sizeof(layouts[0]); l++) {
			uint64_t table = 0;
			uint32_t highest = 0;
			uint64_t chunk0 = 0;

			if (hv_read_u64(mem, target + layouts[l].list, &table) != 0)
				continue;
			if (table < 0x10000 || table > 0x7fffffffffffULL)
				continue;

			if (hv_read_u32(mem, target + layouts[l].highest, &highest) != 0)
				continue;
			/* An entity count above 64k is not an entity count. */
			if (highest == 0 || highest > 65536)
				continue;

			if (hv_read_u64(mem, table, &chunk0) != 0)
				continue;
			if (chunk0 < 0x10000 || chunk0 > 0x7fffffffffffULL)
				continue;

			r->found = 1;
			r->global_addr = addr;
			r->entity_system = target;
			r->list_off = layouts[l].list;
			r->highest_off = layouts[l].highest;
			r->highest_index = highest;
			r->chunk_table = table;
			r->first_chunk = chunk0;
			snprintf(r->note, sizeof(r->note),
				 "layout list=+0x%x highest=+0x%x, %d pointers tried",
				 layouts[l].list, layouts[l].highest, tried);
			return 0;
		}
	}

	snprintf(r->note, sizeof(r->note),
		 "scanned %d candidate pointers in .data, none consistent",
		 tried);
	return 1;
}

/*
 * Read the fields of one entity at a given base, given a hypothesis for the
 * layout. Returns 1 if it looks like a live player.
 */
static int probe_entity(hv_ctx *mem, uint64_t slot, const cs2_offsets *h,
			float out_origin[3], int *out_health, int *out_team)
{
	float origin[3];
	uint32_t health32 = 0;
	uint8_t team8 = 0;

	if (hv_read(mem, slot + h->off_origin, origin, sizeof(origin)) != 0)
		return 0;
	if (!origin_sane(origin))
		return 0;

	if (hv_read_u32(mem, slot + h->off_health, &health32) != 0)
		return 0;
	/* Health is a small positive int; the high half must be zero or it is not
	 * an int field at all. */
	if (health32 == 0 || health32 > 100)
		return 0;

	if (hv_read_u8(mem, slot + h->off_team, &team8) != 0)
		return 0;
	if (team8 != 2 && team8 != 3)
		return 0;

	if (out_origin != NULL) {
		out_origin[0] = origin[0];
		out_origin[1] = origin[1];
		out_origin[2] = origin[2];
	}
	if (out_health != NULL)
		*out_health = (int)health32;
	if (out_team != NULL)
		*out_team = team8;
	return 1;
}

int discover_layout(hv_ctx *mem, const discover_opts *o, discover_result *r)
{
	cs2_offsets h;
	uint32_t best_stride = 0;
	int best_hits = 0;
	int best_identity = 0;
	int any_hits = 0;

	(void)o;

	if (!r->found) {
		snprintf(r->note, sizeof(r->note), "no entity system to analyse");
		return 1;
	}

	r->chunk_entities = DEFAULT_CHUNK_ENTITIES;

	/*
	 * Field-offset hypotheses. Rather than scan 0x2000 bytes per stride per
	 * entity (which is what makes these tools slow), the known-stable members
	 * are tried first: health and team are the same across builds far more
	 * often than origin is.
	 *
	 * These are *candidates*. The winner is chosen by how many entities
	 * validate simultaneously, so a wrong candidate loses rather than being
	 * accepted on one lucky hit.
	 */
	static const uint32_t health_c[] = { 0x344, 0x340, 0x334, 0x338, 0x330 };
	static const uint32_t team_c[]   = { 0x3f3, 0x3f0, 0x3eb, 0x3e8 };
	static const uint32_t origin_c[] = { 0x1324, 0x1320, 0x131c, 0x130c, 0x1214 };

	memset(&h, 0, sizeof(h));

	for (size_t hi = 0; hi < sizeof(health_c) / sizeof(health_c[0]); hi++) {
		for (size_t ti = 0; ti < sizeof(team_c) / sizeof(team_c[0]); ti++) {
			for (size_t oi = 0; oi < sizeof(origin_c) / sizeof(origin_c[0]); oi++) {
				/* Two identity hypotheses: by-value and via-pointer. */
				for (int identity = 0; identity <= 1; identity++) {
					for (uint32_t stride = 0x20; stride <= 0x400; stride += 8) {
						int hits = 0;

						h.off_health = health_c[hi];
						h.off_team = team_c[ti];
						h.off_origin = origin_c[oi];
						h.off_identity_entity = identity ? 0x48 : 0;

						for (int idx = 1; idx < 512 && hits < 12; idx++) {
							int chunk = idx / (int)r->chunk_entities;
							int slot = idx % (int)r->chunk_entities;
							uint64_t chunk_ptr = 0;
							uint64_t slot_addr;

							if (hv_read_u64(mem, r->chunk_table + chunk * 8,
									&chunk_ptr) != 0)
								continue;
							if (chunk_ptr == 0)
								continue;

							slot_addr = chunk_ptr + (uint64_t)slot * stride;

							if (h.off_identity_entity != 0) {
								uint64_t ent = 0;
								if (hv_read_u64(mem, slot_addr + h.off_identity_entity,
										&ent) != 0 || ent == 0)
									continue;
								slot_addr = ent;
							}

							if (probe_entity(mem, slot_addr, &h, NULL, NULL, NULL))
								hits++;
						}

						if (hits > 0)
							any_hits++;

						/*
						 * Tie-break: a 3-float vector validates equally at
						 * off and off+4, so equal hit counts are ambiguous.
						 * Prefer the earlier candidate in the list, which is
						 * the conventional first member of a vec3, and among
						 * equals prefer the smaller offset - a vector never
						 * starts mid-vector.
						 */
						if (hits > best_hits ||
						    (hits == best_hits && hits > 0 &&
						     (r->off_origin == 0 || h.off_origin < r->off_origin))) {
							best_hits = hits;
							best_stride = stride;
							best_identity = identity;
							r->off_health = h.off_health;
							r->off_team = h.off_team;
							r->off_origin = h.off_origin;
							r->off_identity_entity = h.off_identity_entity;
						}
					}
				}
			}
		}
	}

	r->stride_candidates = any_hits;
	r->stride_validated = best_hits;

	if (best_hits < 2) {
		/*
		 * Fewer than two simultaneous players is not a layout. Either the
		 * session has no bots, or every hypothesis is wrong. Saying so is
		 * better than emitting the best-scoring guess.
		 */
		snprintf(r->note, sizeof(r->note),
			 "best hypothesis validated %d entities; need at least 2 "
			 "(is a bot match running?)", best_hits);
		return 1;
	}

	r->chunk_stride = best_stride;
	if (best_identity)
		r->off_identity_entity = 0x48;

	snprintf(r->note, sizeof(r->note),
		 "stride 0x%x, %s layout, %d entities validated",
		 best_stride, best_identity ? "via-identity" : "by-value", best_hits);
	return 0;
}

int discover_all(hv_ctx *mem, const discover_opts *o, cs2_offsets *out,
		 discover_result *r)
{
	if (discover_entity_system(mem, o, r) != 0)
		return 1;

	/*
	 * The entity-system layout offsets are part of what stage 1 validated, so
	 * they are carried in the note and re-derived here. Keeping them in one
	 * place would be cleaner; the reason they are not is that stage 1 must try
	 * several layouts and only the winner is known afterwards.
	 */
	if (discover_layout(mem, o, r) != 0)
		return 2;

	cs2_offsets_clear(out);
	out->off_entity_list = r->list_off;
	out->off_highest_index = r->highest_off;
	out->chunk_stride = r->chunk_stride;
	out->chunk_entities = r->chunk_entities;
	out->off_identity_entity = r->off_identity_entity;
	out->off_health = r->off_health;
	out->off_team = r->off_team;
	out->off_origin = r->off_origin;
	/*
	 * dw_entity_system is the RVA of the *global pointer*, not of the entity
	 * system it points at. Stage 1 records where the pointer was found, so the
	 * conversion uses global_addr - using entity_system here would produce an
	 * RVA pointing into heap memory, which reads as a valid-looking offset and
	 * is wrong by however far the heap sits from the image.
	 */
	out->dw_entity_system = r->global_addr - o->client_base;
	return 0;
}

void discover_print(const discover_result *r)
{
	printf("entity system : %s\n", r->found ? "found" : "NOT FOUND");
	if (r->found) {
		printf("  base        : 0x%llx\n", (unsigned long long)r->entity_system);
		printf("  chunk table : 0x%llx\n", (unsigned long long)r->chunk_table);
		printf("  first chunk : 0x%llx\n", (unsigned long long)r->first_chunk);
		printf("  highest idx : %u\n", r->highest_index);
	}
	printf("layout        : stride=0x%x entities=%u identity=%s\n",
	       r->chunk_stride, r->chunk_entities,
	       r->off_identity_entity ? "via-identity" : "by-value");
	printf("fields        : health=0x%x team=0x%x origin=0x%x\n",
	       r->off_health, r->off_team, r->off_origin);
	printf("validation    : %d entities at best stride (%d hypotheses had hits)\n",
	       r->stride_validated, r->stride_candidates);
	printf("note          : %s\n", r->note);
}
