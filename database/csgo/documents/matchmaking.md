# `matchmaking.dll` — Source 2 matchmaking and session layer

Reverse-engineering notes. Every address is an RVA in
`csgo/bin/win64/matchmaking.dll`, `ImageBase = 0x180000000`.

Marked **inferred** where a name is not proven by an RTTI descriptor, a
`Source2` interface string, a `__FILE__` literal, or a vtable layout.

---

## 1. Identity

| Property | Value |
|---|---|
| File | `matchmaking.dll` |
| Size on disk | **1,890,968** bytes |
| `SizeOfImage` | 2,072,576 (`0x1FA000`) |
| SHA256 | see `index/manifest.json` (authoritative) |
| ImageBase | `0x180000000` |
| Entry point RVA | `0x1127b4` |
| PE timestamp | 1793662285 |
| PDB | `...\matchmaking\_vpc_matchmaking_csgo\default\win64\_msvc_\Retail\matchmaking.pdb` |
| `.pdata` records | 6,305 |
| Merged real functions | **3,858** |
| Exports | 6 (standard Source 2 module ABI) |
| Import DLLs | 3: `steam_api64.dll` (7), `tier0.dll` (188), `KERNEL32.dll` (85) |
| RTTI types | 363 |

The `_vpc_matchmaking_csgo` PDB path places it in `src/game/matchmaking/`.

### Third-party code embedded

The `__FILE__` literals include seven protobuf 3.21.8 headers from
`U:\thirdpartycode\nonredist\protobuf\protobuf-3.21.8\src\google/protobuf\`:

```
descriptor.h, dynamic_message.h, extension_set_inl.h, map_field.h,
map_field_inl.h, parse_context.h, reflection_internal.h
```

So the module statically links protobuf. This matters: the Steam game-coordinator
(GC) and match framework messages are protobuf-encoded, and the message
definitions are inside the binary (the same finding `networksystem.md` made for
network messages).

---

## 2. What this module is

`matchmaking.dll` is the **session and lobby layer**: it searches for, creates,
joins and hosts matches, and it carries the GC (game-coordinator) client that
issues matchmaking tickets and routes GC messages.

Evidence:

- Imports exactly seven Steam API functions, all lifecycle/callback:
  `SteamAPI_RegisterCallback`, `RegisterCallResult`, `Unregister*`,
  `GetHSteamUser`, `SteamInternal_ContextInit`,
  `SteamInternal_FindOrCreateUserInterface`. It uses Steam's callback plumbing,
  not its raw matchmaking API directly.
- The RTTI set is a complete session framework (§4).

---

## 3. Interfaces actually registered

The `index/ifaces/matchmaking.txt` list (90 names) is a string-scan superset.
Locating stubs that `jmp` into `CreateInterface` (`0x108b60`; stubs target the
thunk at `0x108b40`) gives **two** registrations:

| Interface | Stub RVA |
|---|---|
| `GameTypes001` | `0x2095` |
| `MATCHFRAMEWORK_001` | `0x2be5` |

Two interfaces is plausible for this module: `MATCHFRAMEWORK_001` is the whole
match framework behind one interface, and `GameTypes001` exposes the game-type
enumeration. The framework's internals are reached through
`MATCHFRAMEWORK_001`'s vtable rather than through separate interfaces.

---

## 4. Class hierarchy (RTTI, exact names)

Three root abstractions organise the module:

**Match framework**

| Class | Role |
|---|---|
| `CMatchFramework` | root object, owns the system |
| `CMatchSystem` | the subsystem |
| `CMatchTitle`, `CMatchTitleGameSettingsMgr` | per-title configuration |
| `CMatchExtensions` | extension registry |
| `CMatchEventsSubscription` | event subscription |
| `CMatchNetworkMsgControllerBase` | network message dispatch |

**Sessions** — the core state machine, one class per role:

| Class | Role |
|---|---|
| `CMatchSessionOnlineSearch` | the client searching |
| `CMatchSessionOnlineTeamSearch` | team/party searching |
| `CMatchSessionOnlineHost` | hosting a session |
| `CMatchSessionOnlineClient` | joined as client |
| `CMatchSessionOfflineCustom` | offline/custom, no GC |

**Searchers**

| Class | Role |
|---|---|
| `CMatchSearcher` | base |
| `CMatchSearcher_OnlineSearch` | online |
| `CMatchSearcher_OnlineTeamSearch` | team |
| `CDsSearcher` | dedicated-server search |

**GC client** (a full game-coordinator implementation)

| Class | Role |
|---|---|
| `CGCClient`, `CGCClientJob` | GC connection and job queue |
| `CGCClientSharedObjectCache`, `...TypeCache` | the shared-object cache (inventory, stats, etc.) |
| `CGCSOCacheSubscribedJob`, `CGCSOCreateJob`, `CGCSODestroyJob`, `CGCSOUpdateJob`, `CGCSOUpdateMultipleJob`, `CGCSOCacheUnsubscribedJob`, `CGCSOCacheSubscriptionCheck` | SO cache job types |
| `CGCToGCMsgMasterAck`, `...StartupComplete`, `...Routed`, `...RoutedReply` | GC-to-GC routing |
| `CGCClientJobUpdateStats` | stats submission |

The presence of the full `CGCClient` plus the SO cache means this module is where
**matchmaking tickets, trust/XP/rank data and the GC connection** live — not just
lobby plumbing.

---

## 5. ConVars (56 recovered)

The scan pairs each name with the help string that follows it in `.rdata`. Where
the help text was not adjacent it is omitted rather than guessed.

Search-behaviour cvars:

| cvar | RVA | Help |
|---|---|---|
| `mm_player_search_requests_limit` | `0x15fdc0` | Interval between players searches. |
| `mm_player_search_update_interval` | `0x15fe08` | Interval between LAN discovery pings. |
| `mm_player_search_lan_ping_interval` | `0x15fe58` | Duration of LAN discovery ping phase. |
| `mm_player_search_lan_ping_duration` | `0x15fea8` | — |
| `mm_player_search_count` | `0x1608e0` | — |

Session/host cvars:

| cvar | RVA | Help |
|---|---|---|
| `mm_use_p2p_for_listen_server` | `0x1613c8` | — |
| `mm_ignored_sessions_forget_time` | `0x162078` | — |
| `mm_ignored_sessions_forget_pass` | `0x162098` | — |
| `mm_ignored_sessions_reset` | `0x1620d0` | — |
| `mm_session_sys_delay_create` | `0x162ee0` | — |
| `mm_session_sys_delay_create_host` | `0x162f00` | — |
| `mm_session_sys_connect_timeout` | `0x162f28` | — |

Debug cvars: `mm_sv_load_test` (`0x1020`), `mm_title_debug_version`
(`0x10d0`), `mm_debug_friend_rp` (`0x1608f8`), `cl_names_debug` (`0x1608d0`).
`mm_csgo_community_*` (`0x1180`) controls community-server human-player thresholds.

Caveat: some help strings in the raw scan belong to *neighbouring* registration
sites (e.g. `JoinInviteSession: sessionid = %llx` sits next to
`mm_events_listeners_validation`, which is a log format string, not its help).
Only the entries with genuinely descriptive help text are reproduced above; the
rest are listed by name and RVA without a claimed meaning.

---

## 6. Message flow (inferred, consistent with the class set)

```
CMatchSessionOnlineSearch
   -> CMatchSearcher_OnlineSearch       (finds candidates)
   -> GC: matchmaking ticket            (CGCClient, protobuf)
   -> CGCToGCMsgRouted                  (routed to the GC master)
   -> server reservation
   -> CMatchSessionOnlineClient         (connect)
```

and for hosting:

```
CMatchSessionOnlineHost  ->  mm_session_sys_delay_create_host
                         ->  CMatchNetworkMsgControllerBase  (announce)
```

This ordering is **inferred from the class names and cvars**, not from a
decompiled call graph. It is the one part of this document that is not
address-anchored, and is marked accordingly.

---

## 7. Unknowns

1. **`MATCHFRAMEWORK_001` vtable** — not walked; slot count and method purposes
   unknown.
2. **The GC message IDs** — the protobuf descriptors are in the image, but the
   `CGCToGCMsg*` payload schemas were not extracted. The method used in
   `networksystem.md` (parsing `FileDescriptorProto` blobs) would recover them.
3. **Ticket structure** — what fields a matchmaking ticket carries is not
   established.
4. **Trust/VAC integration** — `CGCClientJobUpdateStats` exists, but no VAC
   submission path was identified here. VAC is likely in a module not yet
   documented.
5. **Only 2 interfaces found** — the detector is conservative; a third may use a
   stub shape it does not recognise.
6. **Section §6 is inferred**, not proven by decompilation.

The highest-value next step is parsing the embedded protobuf descriptors, which
turns unknowns 2 and 3 into a complete message catalogue with exact IDs.
