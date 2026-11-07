/*
 * discover.h - find the entity system and field offsets by measurement.
 *
 * Every number this produces is derived from observations, not from a table
 * copied off the internet. That matters because CS2 is schema-driven: the
 * offsets move every patch, and a table that is one patch stale produces reads
 * that succeed and values that are wrong.
 *
 * The strategy is elimination, not identification:
 *
 *   dw_entity_system   candidates are qwords in the data section. A candidate is
 *                      accepted only if its target looks like an entity system:
 *                      a pointer to a chunk table whose first chunk pointer is
 *                      readable, and a highest-index field in 1..65536.
 *
 *   chunk_stride       candidates are byte strides. A stride is accepted only if
 *                      *several* entities simultaneously pass the player test
 *                      (health 1..100, team 2 or 3, finite non-zero origin).
 *                      One entity passing is coincidence; ten is a layout.
 *
 *   field offsets      found by scanning a validated entity for the shapes:
 *                      a float triple that is finite and differs between two
 *                      entities (origin), a byte in 1..100 (health), a byte that
 *                      is 2 or 3 and differs across teams (team).
 *
 * Everything here takes an hv_ctx so it can run against the hypervisor or
 * against a synthetic image. See selftest.c for the synthetic case.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "cs2cfg.h"
#include "hvmem.h"

typedef struct discover_result
{
	int      found;              /* 1 if an entity system was located */
	uint64_t entity_system;      /* address of CGameEntitySystem */
	uint64_t global_addr;        /* address of the pointer that led here */
	uint32_t highest_index;
	uint64_t chunk_table;
	uint64_t first_chunk;        /* first non-null chunk pointer */
	uint32_t list_off;           /* entity-system layout that validated */
	uint32_t highest_off;

	/* Best candidate, zero if not determined. */
	uint32_t chunk_stride;
	uint32_t chunk_entities;
	uint32_t off_identity_entity;
	uint32_t off_health;
	uint32_t off_team;
	uint32_t off_origin;
	uint32_t off_lifestate;

	/* Diagnostics: how many candidates were tried and why the best won. */
	int      stride_candidates;
	int      stride_validated;   /* entities that passed at the winning stride */
	char     note[256];
} discover_result;

typedef struct discover_opts
{
	uint64_t client_base;
	uint64_t client_size;        /* SizeOfImage, to bound the scan */
	uint32_t data_rva;           /* start of the data section */
	uint32_t data_size;
	int      verbose;
} discover_opts;

/*
 * Locate the entity system. Fills result->entity_system, highest_index,
 * chunk_table and first_chunk. Returns 0 when found.
 */
int discover_entity_system(hv_ctx *mem, const discover_opts *o,
			   discover_result *r);

/*
 * Given a located entity system, find the chunk layout and field offsets.
 *
 * Requires at least two live entities to distinguish a real field from a
 * constant. In a bot match with `bot_quota 10` that is satisfied; in the main
 * menu it is not, which is why this reports "not in a match" rather than a
 * guess.
 */
int discover_layout(hv_ctx *mem, const discover_opts *o, discover_result *r);

/* Convenience: both stages, then fill a cs2_offsets. */
int discover_all(hv_ctx *mem, const discover_opts *o, cs2_offsets *out,
		 discover_result *r);

/* Human-readable dump of a result. */
void discover_print(const discover_result *r);
