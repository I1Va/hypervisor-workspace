/*
 * cs2ent.h - read player state out of the running game.
 *
 * Design rules, each learned from a way these readers normally fail:
 *
 * 1. Every read is validated before it is believed. An entity slot that does
 *    not look like a live player (health outside 1..100, team not 2/3, origin
 *    outside the map) is reported as "not a player", not as a player with
 *    garbage stats. A wallhack that draws nonsense is worse than one that
 *    draws nothing, because the nonsense is indistinguishable from a real
 *    reading until you act on it.
 *
 * 2. Nothing is cached across ticks. Entity slots are recycled; a slot that held
 *    a player last tick may hold a projectile now, and a stale handle read
 *    returns the projectile's bytes interpreted as a player.
 *
 * 3. The offline guard is part of this layer, not a wrapper. If the tool could
 *    be pointed at a live match by forgetting a flag, the flag would eventually
 *    be forgotten.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#include "cs2cfg.h"
#include "hvmem.h"

typedef struct vec3
{
	float x, y, z;
} vec3;

typedef struct player
{
	int      index;        /* entity index */
	int      health;
	int      team;         /* 2 = T, 3 = CT */
	int      alive;
	vec3     origin;
	vec3     eye;          /* origin + view offset, for line of sight */
	uint32_t weapon_id;    /* active weapon definition index, 0 if unknown */
	uint64_t pawn;         /* pawn address, for follow-up reads */
} player;

typedef struct entity_system
{
	uint64_t base;         /* CGameEntitySystem* */
	uint64_t chunk_table;  /* pointer to the chunk pointer array */
	int      highest;      /* highest index in use */
} entity_system;

typedef struct cs2
{
	hv_ctx        mem;
	cs2_offsets   off;
	uint64_t      client_base;
	entity_system es;
} cs2;

/* Non-zero when the game is in an online/VAC-secured session. */
int cs2_online_session(const cs2 *c);

/*
 * Resolve the entity system. Returns 0 on success.
 * Fails loudly when the offsets file does not match the loaded client.dll.
 */
int cs2_init(cs2 *c, const cs2_offsets *off, uint64_t client_base, uint64_t cr3);

/*
 * Read up to `cap` players into `out`. Returns the count, or -1 on error.
 *
 * Only entities that pass validation are returned. `scanned` receives how many
 * slots were examined, so a caller can tell "no players" from "read nothing".
 */
int cs2_players(cs2 *c, player *out, int cap, int *scanned);

/* Human-readable name for a team id. */
const char *cs2_team_name(int team);
