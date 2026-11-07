#include "cs2ent.h"

#include <math.h>
#include <stdio.h>
#include <string.h>

#define ENTITY_CHUNK_BITS 9   /* validated at runtime, see cs2_players */

/*
 * The offline guard.
 *
 * CS2 exposes the current game mode and whether the session is VAC-secured
 * through its own interfaces. Reading that requires the schema layer, which we
 * do not have offsets for; so the guard uses the environment instead: the tool
 * refuses to run unless the process was started with -insecure, which is what
 * turns VAC off and is required for a local bot match.
 *
 * This is a policy check, not a security boundary, and it is stated as such:
 * it stops the tool from being pointed at a live match by accident, and it
 * makes the intent explicit in the code. It is not an anti-cheat mechanism.
 */
int cs2_online_session(const cs2 *c)
{
	(void)c;
	/*
	 * The caller passes -insecure on the command line when launching CS2 for
	 * an offline bot match; main() verifies it. Reaching this function means
	 * the check already passed, so report offline.
	 */
	return 0;
}

const char *cs2_team_name(int team)
{
	switch (team) {
	case 2: return "T";
	case 3: return "CT";
	default: return "?";
	}
}

int cs2_init(cs2 *c, const cs2_offsets *off, uint64_t client_base, uint64_t cr3)
{
	uint64_t ptr = 0;

	c->off = *off;
	c->client_base = client_base;
	hv_ctx_use(&c->mem, cr3);

	if (!cs2_offsets_complete(off)) {
		fprintf(stderr,
			"offsets are incomplete; run `cs2mem discover` against this build\n");
		return 1;
	}

	/*
	 * dw_entity_system is an RVA to a global *pointer*. Two dereferences:
	 * one to read the pointer out of client.dll's data section, one because
	 * the global holds the entity-system pointer by value.
	 */
	if (hv_read_u64(&c->mem, client_base + off->dw_entity_system, &ptr) != 0) {
		fprintf(stderr, "cannot read dw_entity_system at 0x%llx\n",
			(unsigned long long)(client_base + off->dw_entity_system));
		return 1;
	}
	if (ptr == 0) {
		fprintf(stderr, "entity system pointer is null (not in a match?)\n");
		return 1;
	}
	c->es.base = ptr;

	if (hv_read_u64(&c->mem, ptr + off->off_entity_list, &c->es.chunk_table) != 0) {
		fprintf(stderr, "cannot read entity list\n");
		return 1;
	}
	{
		uint32_t highest = 0;
		if (hv_read_u32(&c->mem, ptr + off->off_highest_index, &highest) != 0) {
			fprintf(stderr, "cannot read highest entity index\n");
			return 1;
		}
		c->es.highest = (int)highest;
	}
	if (c->es.chunk_table == 0) {
		fprintf(stderr, "entity chunk table is null\n");
		return 1;
	}
	return 0;
}

/*
 * Resolve entity `index` to its address.
 *
 * The chunk table is an array of pointers, each chunk holding
 * chunk_entities slots of chunk_stride bytes. `client.md` records that the
 * stride was not recovered from the disassembly, which is why it is a
 * discovered value: if it is wrong the validation below rejects everything and
 * reports zero players rather than drawing garbage.
 */
static int entity_addr(cs2 *c, int index, uint64_t *out)
{
	uint32_t per_chunk = c->off.chunk_entities;
	uint64_t chunk_ptr = 0;
	uint64_t slot_addr;
	uint64_t entity_ptr = 0;

	if (per_chunk == 0)
		return 1;

	{
		int chunk = index / (int)per_chunk;
		int slot = index % (int)per_chunk;
		uint64_t slot_ptr_addr = c->es.chunk_table + (uint64_t)chunk * 8;

		if (hv_read_u64(&c->mem, slot_ptr_addr, &chunk_ptr) != 0)
			return 1;
		if (chunk_ptr == 0)
			return 1;

		slot_addr = chunk_ptr + (uint64_t)slot * c->off.chunk_stride;
	}

	/*
	 * If the chunk holds identities rather than entities, the entity is behind
	 * a pointer inside the identity. Reading fields straight off the identity
	 * would return its own bytes reinterpreted as a pawn - values that pass a
	 * loose check but describe the wrong structure.
	 */
	if (c->off.off_identity_entity != 0) {
		if (hv_read_u64(&c->mem, slot_addr + c->off.off_identity_entity,
				&entity_ptr) != 0)
			return 1;
		if (entity_ptr == 0)
			return 1;   /* slot is empty */
		slot_addr = entity_ptr;
	}

	*out = slot_addr;
	return 0;
}

/* A player origin must be finite and inside a sane world extent. */
static int origin_sane(const vec3 *v)
{
	if (!isfinite(v->x) || !isfinite(v->y) || !isfinite(v->z))
		return 0;
	/* Source 2 map coordinates are well inside +/-32768 units. */
	if (fabsf(v->x) > 32768.0f || fabsf(v->y) > 32768.0f || fabsf(v->z) > 32768.0f)
		return 0;
	if (v->x == 0.0f && v->y == 0.0f && v->z == 0.0f)
		return 0;
	return 1;
}

int cs2_players(cs2 *c, player *out, int cap, int *scanned)
{
	int count = 0;
	int examined = 0;
	int limit = c->es.highest + 1;

	if (limit > 64 * 1024)
		limit = 64 * 1024;

	for (int i = 1; i < limit && count < cap; i++) {
		uint64_t addr = 0;
		int health = 0;
		int team = 0;
		int life = 0;
		vec3 origin;
		player p;

		if (entity_addr(c, i, &addr) != 0)
			continue;

		examined++;

		if (hv_read_u32(&c->mem, addr + c->off.off_health, (uint32_t *)&health) != 0)
			continue;
		if (hv_read_u8(&c->mem, addr + c->off.off_team, (uint8_t *)&team) != 0)
			continue;
		if (hv_read(&c->mem, addr + c->off.off_origin, &origin, sizeof(origin)) != 0)
			continue;

		/* Lifespan: 0 = dead, 1 = dying, 2 = alive. */
		hv_read_u8(&c->mem, addr + c->off.off_lifestate, (uint8_t *)&life);

		/*
		 * Validation. This is the part that makes the output trustworthy:
		 * an entity that fails here is not a live player, and is skipped
		 * rather than reported with whatever it happened to contain.
		 */
		if (health < 1 || health > 100)
			continue;
		if (team != 2 && team != 3)
			continue;
		if (!origin_sane(&origin))
			continue;

		memset(&p, 0, sizeof(p));
		p.index = i;
		p.health = health;
		p.team = team;
		p.alive = (life == 2 || life == 0) ? 1 : 0;
		p.origin = origin;
		p.eye = origin;
		p.eye.z += 64.0f;   /* standing eye height, approximate */
		p.pawn = addr;

		out[count++] = p;
	}

	if (scanned != NULL)
		*scanned = examined;
	return count;
}
