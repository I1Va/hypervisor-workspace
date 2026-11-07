/*
 * cs2mem - read player state from an offline CS2 bot match through the hypervisor.
 *
 * Usage:
 *   cs2mem check
 *       Verify the hypervisor hypercalls work and report the current CR3.
 *
 *   cs2mem modules
 *       Locate cs2.exe, print its PID, CR3 and loaded module bases.
 *
 *   cs2mem probe <rva> [len]
 *       Hexdump client.dll+<rva> through the hypervisor. The sanity check that
 *       reads are actually working before any offset is trusted.
 *
 *   cs2mem players [--json]
 *       Read and print live player state, using cs2mem.ini.
 *
 *   cs2mem discover
 *       Scan client.dll for the entity-system pointer and candidate offsets,
 *       and write cs2mem.ini.
 *
 * Requires: an offline session (CS2 launched with -insecure), administrator
 * rights, and a hypervisor build that includes HYPERCALL_GET_PROCESS_CR3.
 */
#include "cs2cfg.h"
#include "cs2ent.h"
#include "hvmem.h"
#include "hvcalls.h"
#include "target.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *INI = "cs2mem.ini";

/* Overridable so the CR3 walk can be validated against a process you control
 * before it is trusted with the game. */
static const wchar_t *g_exe = L"cs2.exe";

static void hexdump(const uint8_t *b, size_t n, uint64_t base)
{
	for (size_t i = 0; i < n; i += 16) {
		printf("%016llx  ", (unsigned long long)(base + i));
		for (size_t j = 0; j < 16; j++) {
			if (i + j < n)
				printf("%02x ", b[i + j]);
			else
				printf("   ");
			if (j == 7)
				printf(" ");
		}
		printf(" |");
		for (size_t j = 0; j < 16 && i + j < n; j++) {
			uint8_t c = b[i + j];
			printf("%c", (c >= 32 && c < 127) ? c : '.');
		}
		printf("|\n");
	}
}

static int cmd_check(void)
{
	hv_ctx ctx;

	if (hv_ctx_init(&ctx) != 0) {
		printf("FAIL: hypercall path did not return a CR3.\n");
		printf("      Either the hypervisor is not running, or the key does not match\n");
		printf("      (see hvcalls.h). A wrong key still executes CPUID and returns 0.\n");
		return 1;
	}
	printf("OK: hypercalls work, current CR3 = 0x%llx\n",
	       (unsigned long long)ctx.cr3);
	return 0;
}

static int cmd_modules(void)
{
	target t;
	char err[512];

	if (target_open(&t, g_exe, err, sizeof(err)) != 0) {
		printf("FAIL: %s\n", err);
		return 1;
	}
	printf("pid       = %lu\n", (unsigned long)t.pid);
	printf("cr3       = 0x%llx\n", (unsigned long long)t.cr3);
	printf("modules   = %d\n", t.module_count);
	for (int i = 0; i < t.module_count; i++) {
		const module_info *m = &t.modules[i];
		printf("  0x%016llx  %8u  %s\n",
		       (unsigned long long)m->base, m->size, m->name);
	}
	target_close(&t);
	return 0;
}

static int cmd_probe(uint64_t rva, size_t len)
{
	target t;
	char err[512];
	hv_ctx ctx;
	const module_info *client;
	uint8_t buf[256];

	if (len > sizeof(buf))
		len = sizeof(buf);

	if (target_open(&t, g_exe, err, sizeof(err)) != 0) {
		printf("FAIL: %s\n", err);
		return 1;
	}
	client = target_module(&t, "client");
	if (client == NULL) {
		printf("FAIL: client.dll not loaded\n");
		target_close(&t);
		return 1;
	}

	if (hv_ctx_init(&ctx) != 0) {
		printf("FAIL: hypercalls unavailable\n");
		target_close(&t);
		return 1;
	}
	hv_ctx_use(&ctx, t.cr3);

	if (hv_read(&ctx, client->base + rva, buf, len) != 0) {
		printf("FAIL: read of 0x%llx failed (cr3 0x%llx)\n",
		       (unsigned long long)(client->base + rva),
		       (unsigned long long)t.cr3);
		target_close(&t);
		return 1;
	}

	printf("client.dll base 0x%llx, reading +0x%llx:\n",
	       (unsigned long long)client->base, (unsigned long long)rva);
	hexdump(buf, len, client->base + rva);
	target_close(&t);
	return 0;
}

/*
 * The offline guard, enforced rather than documented.
 *
 * `cs2_online_session` in cs2ent.c is a stub that returns 0 because the real
 * answer needs the schema layer we have no offsets for. This is the check that
 * actually runs: read the game's own command line and require -insecure, which
 * is what disables VAC. A match launched without it is a live, secured session
 * and the tool refuses.
 *
 * It is a policy check and it is stated as one: it stops the tool being pointed
 * at a live match by accident or by habit. It is not a security boundary.
 */
static int require_offline(target *t)
{
	char cmdline[2048];

	if (target_command_line(t, cmdline, sizeof(cmdline)) != 0) {
		printf("FAIL: cannot read the game's command line, so the offline\n");
		printf("      requirement cannot be verified. Refusing to run.\n");
		return 1;
	}

	if (strstr(cmdline, "-insecure") == NULL) {
		printf("REFUSED: cs2.exe was not started with -insecure.\n");
		printf("         Command line: %s\n", cmdline);
		printf("\n");
		printf("This tool reads player state for offline bot matches only.\n");
		printf("Launch CS2 with -insecure for a local match, e.g.:\n");
		printf("  cs2.exe -insecure +map de_dust2 +bot_quota 10\n");
		return 1;
	}
	return 0;
}

static int cmd_players(int json)
{
	target t;
	cs2_offsets off;
	cs2 c;
	char err[512];
	const module_info *client;
	player players[64];
	int scanned = 0;
	int n;

	if (target_open(&t, g_exe, err, sizeof(err)) != 0) {
		printf("FAIL: %s\n", err);
		return 1;
	}
	client = target_module(&t, "client");
	if (client == NULL) {
		printf("FAIL: client.dll not loaded\n");
		target_close(&t);
		return 1;
	}

	if (cs2_offsets_load(&off, INI, err, sizeof(err)) != 0) {
		printf("FAIL: %s\n", err);
		printf("      run `cs2mem discover` first\n");
		target_close(&t);
		return 1;
	}

	memset(&c, 0, sizeof(c));
	if (hv_ctx_init(&c.mem) != 0) {
		printf("FAIL: hypercalls unavailable\n");
		target_close(&t);
		return 1;
	}
	hv_ctx_use(&c.mem, t.cr3);

	if (require_offline(&t) != 0) {
		target_close(&t);
		return 1;
	}

	if (cs2_init(&c, &off, client->base, t.cr3) != 0) {
		target_close(&t);
		return 1;
	}

	n = cs2_players(&c, players, 64, &scanned);
	if (n < 0) {
		printf("FAIL: player scan failed\n");
		target_close(&t);
		return 1;
	}

	if (json) {
		printf("{\"scanned\":%d,\"players\":[", scanned);
		for (int i = 0; i < n; i++) {
			printf("%s{\"index\":%d,\"team\":\"%s\",\"health\":%d,"
			       "\"alive\":%d,\"x\":%.2f,\"y\":%.2f,\"z\":%.2f}",
			       i ? "," : "", players[i].index,
			       cs2_team_name(players[i].team), players[i].health,
			       players[i].alive, players[i].origin.x,
			       players[i].origin.y, players[i].origin.z);
		}
		printf("]}\n");
	} else {
		printf("scanned %d slots, %d players\n", scanned, n);
		printf("%-6s %-4s %-4s %-6s %-22s\n",
		       "index", "team", "hp", "alive", "origin");
		for (int i = 0; i < n; i++) {
			printf("%-6d %-4s %-4d %-6d (%.1f, %.1f, %.1f)\n",
			       players[i].index, cs2_team_name(players[i].team),
			       players[i].health, players[i].alive,
			       players[i].origin.x, players[i].origin.y,
			       players[i].origin.z);
		}
	}

	target_close(&t);
	return 0;
}

static void usage(void)
{
	printf("usage: cs2mem [--exe NAME] <check|modules|probe <rva> [len]|players [--json]|discover>\n");
	printf("\n");
	printf("  check      verify hypercalls and print the current CR3\n");
	printf("  modules    find cs2.exe, print PID, CR3 and module bases\n");
	printf("  probe      hexdump client.dll+rva through the hypervisor\n");
	printf("  players    read live player state (needs %s)\n", INI);
	printf("  discover   scan for the entity system and offsets, write %s\n", INI);
	printf("\n");
	printf("Offline only: launch CS2 with -insecure for a local bot match.\n");
}

int main(int argc, char **argv)
{
	/* --exe NAME is global, so strip it before command dispatch. */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--exe") == 0 && i + 1 < argc) {
			static wchar_t buf[MAX_PATH];
			MultiByteToWideChar(CP_ACP, 0, argv[i + 1], -1, buf, MAX_PATH);
			g_exe = buf;
			for (int j = i; j < argc - 2; j++)
				argv[j] = argv[j + 2];
			argc -= 2;
			break;
		}
	}

	if (argc < 2) {
		usage();
		return 2;
	}

	if (strcmp(argv[1], "check") == 0)
		return cmd_check();
	if (strcmp(argv[1], "modules") == 0)
		return cmd_modules();
	if (strcmp(argv[1], "probe") == 0) {
		if (argc < 3) {
			usage();
			return 2;
		}
		{
			uint64_t rva = strtoull(argv[2], NULL, 0);
			size_t len = argc > 3 ? (size_t)strtoul(argv[3], NULL, 0) : 64;
			return cmd_probe(rva, len);
		}
	}
	if (strcmp(argv[1], "players") == 0) {
		int json = (argc > 2 && strcmp(argv[2], "--json") == 0);
		return cmd_players(json);
	}
	if (strcmp(argv[1], "discover") == 0) {
		printf("discover: not implemented yet - see README.md\n");
		return 3;
	}

	usage();
	return 2;
}
