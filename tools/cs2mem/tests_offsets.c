/* Offsets-parser tests. Runs on the host, no Windows needed:
 *   cc -O2 -I. -o tests_offsets tests_offsets.c cs2cfg.c && ./tests_offsets
 * Expected: via-identity 1 1, by-value 1 1, partial 0 0, typo rejected.
 */
#include "cs2cfg.h"
#include <stdio.h>
#include <string.h>

static const char *HASH64 =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static void write_full(const char *p, int identity_zero)
{
	FILE *f = fopen(p, "w");
	fprintf(f, "client_sha256=%s\n", HASH64);
	fprintf(f, "dw_entity_system=0x1a2b3c\n");
	fprintf(f, "off_entity_list=0x10\noff_highest_index=0x14\n");
	fprintf(f, "chunk_stride=0x78\nchunk_entities=512\n");
	fprintf(f, "off_identity_entity=0x%x\n", identity_zero ? 0 : 0x48);
	fprintf(f, "off_health=0x344\noff_team=0x3f3\noff_origin=0x1324\n");
	fprintf(f, "off_lifestate=0x25\noff_weapon_services=0x11e0\n");
	fprintf(f, "off_pawn_handle=0x6bc\noff_is_alive=0x7f0\n");
	fprintf(f, "off_handle_serial=0x10\n");
	fclose(f);
}

int main(void)
{
	cs2_offsets o;
	char err[512];
	const char *p = "/tmp/opencode/t.ini";
	int rc;

	write_full(p, 0);
	rc = cs2_offsets_load(&o, p, err, sizeof(err));
	printf("via-identity: load=%d complete=%d (expect 1 1)\n",
	       rc, cs2_offsets_complete(&o));

	/* The case that was broken: identity offset 0 is a valid by-value layout. */
	write_full(p, 1);
	rc = cs2_offsets_load(&o, p, err, sizeof(err));
	printf("by-value:     load=%d complete=%d (expect 1 1)\n",
	       rc, cs2_offsets_complete(&o));

	/* A field omitted entirely must make it incomplete. */
	{
		FILE *f = fopen(p, "w");
		fprintf(f, "client_sha256=%s\n", HASH64);
		fprintf(f, "dw_entity_system=0x1a2b3c\n");
		fprintf(f, "off_identity_entity=0\n");
		fclose(f);
	}
	rc = cs2_offsets_load(&o, p, err, sizeof(err));
	printf("partial:      load=%d complete=%d (expect 0 0)\n",
	       rc, cs2_offsets_complete(&o));

	/* Unknown key still rejected. */
	{
		FILE *f = fopen(p, "w");
		fprintf(f, "off_heath=0x340\n");
		fclose(f);
	}
	rc = cs2_offsets_load(&o, p, err, sizeof(err));
	printf("typo:         load=%d (expect 1) err=%s\n", rc, err);

	return 0;
}
