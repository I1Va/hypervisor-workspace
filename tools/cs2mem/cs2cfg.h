/*
 * cs2cfg.h - the offset table, kept in a file rather than compiled in.
 *
 * Why a file: CS2 is schema-driven and every patch moves these numbers. A tool
 * with baked offsets is correct for one build and silently wrong for the next,
 * and "silently wrong" here means reading a plausible-looking float that is not
 * a position. So the offsets are data, they carry a build id, and the tool
 * refuses to run when the id does not match the loaded client.dll.
 *
 * Nothing in this file is a verified value. `discover` fills it in by scanning;
 * until then every field is zero and the reader refuses.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct cs2_offsets
{
	/*
	 * Build identity. Hash of the on-disk client.dll the offsets were found
	 * against. The tool compares it to the running module's file hash and
	 * refuses on mismatch - a mismatched offset table is the single most
	 * common way these tools produce confident garbage.
	 */
	char     client_sha256[65];

	/* RVA of the global pointer to the entity system, in client.dll. */
	uint64_t dw_entity_system;

	/* Offsets inside CGameEntitySystem. */
	uint32_t off_entity_list;      /* pointer to the chunk array */
	uint32_t off_highest_index;    /* highest entity index in use */

	/*
	 * Entity chunk layout. `client.md` documents that the stride was not
	 * resolved from the disassembly, so it is a discovered value: the reader
	 * takes it as data and the validator checks every candidate before use.
	 */
	uint32_t chunk_stride;         /* bytes between consecutive chunks */
	uint32_t chunk_entities;       /* entity slots per chunk */

	/* Offsets inside a C_BaseEntity / C_CSPlayerPawn. */
	uint32_t off_health;
	uint32_t off_team;
	uint32_t off_origin;           /* vec3, absolute origin */
	uint32_t off_lifestate;
	uint32_t off_weapon_services;  /* -> weapon services, for active weapon */

	/* Offsets inside C_CSPlayerController. */
	uint32_t off_pawn_handle;      /* controller -> pawn handle */
	uint32_t off_is_alive;         /* controller alive flag */

	/* Offsets inside CBaseHandle-adjacent structures. */
	uint32_t off_handle_serial;    /* where the serial bits live */
} cs2_offsets;

/* Zero every field, so an unset offset is distinguishable from offset 0. */
void cs2_offsets_clear(cs2_offsets *o);

/*
 * Load from a simple key=value file. Unknown keys are an error, not ignored:
 * a typo in an offset name that is silently ignored produces a tool that reads
 * the wrong field for ever.
 */
int cs2_offsets_load(cs2_offsets *o, const char *path, char *err, size_t err_cap);

int cs2_offsets_save(const cs2_offsets *o, const char *path);

/*
 * True when every offset the reader needs is non-zero. The reader refuses to
 * run otherwise - a partially filled table is worse than none, because some
 * fields would be read and others silently not.
 */
int cs2_offsets_complete(const cs2_offsets *o);
