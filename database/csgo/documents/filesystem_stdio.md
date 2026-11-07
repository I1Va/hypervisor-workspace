# `filesystem_stdio.dll` — the filesystem layer

Addresses are RVAs in `bin/win64/filesystem_stdio.dll`,
`ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **2,260,120** bytes |
| `SizeOfImage` | 2,277,376 (`0x22C000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0x12cc74` |
| PDB | `...\filesystem\_vpc_filesystem_stdio\default\win64\_msvc_\Retail\filesystem_stdio.pdb` |
| `.pdata` records | 5,660 |
| Merged functions | **3,156** |
| Exports | 6 (module ABI) |
| RTTI types | 70 |

### Imports — the interesting part

| DLL | Symbols |
|---|---|
| `tier0.dll` | 235 |
| `KERNEL32.dll` | 108 |
| `WS2_32.dll` | **6** |
| `steam_api64.dll` | 3 |
| `USER32.dll` | 3 |
| `ADVAPI32.dll` | 3 |

A filesystem module importing **winsock** is the finding. It means file data can
arrive over a socket, not only from disk.

The six imports are exactly the primitive set for a connected byte stream:
`send`, `recv`, `shutdown`, `closesocket`, `WSAGetLastError`, `WSASetLastError`.
That is a **raw TCP client** — there is no `WSAStartup`, no `getaddrinfo`, no
`connect` imported here, so either those are resolved dynamically or this module is
handed an already-connected socket. It is not HTTP: no HTTP library is involved.

## 2. What it is

The VFS: it presents a single namespace over loose files, VPK archives, and
(now) network sources.

| Class | Role |
|---|---|
| `CBaseFileSystem` | the namespace and mount table |
| `CAsyncFileSystem2` | asynchronous I/O |
| `CFileHandle`, `CFileStream`, `CBufferStream` | the stream abstraction |
| `CCompletionQueue` | async completion |
| `CBarrierRequest` | an ordering barrier over async I/O |

`CAsyncFileSystem2` + `CCompletionQueue` + `CBarrierRequest` together are a proper
async I/O engine: requests are queued, completions are reaped, and barriers
enforce ordering where the API needs it. That is why the module is 3,156 functions
for what sounds like `fopen`.

## 3. Interface registered

`CreateInterface` export at `0x11c2e0`; stubs target thunk `0x11c2c0`. One:

| Interface | Stub RVA |
|---|---|
| `VFileSystem017` | `0x49265` |

**`017`** is by far the highest interface revision in the corpus (most are
`001`–`003`, `ResourceSystem013` was second). The filesystem interface has been
revised seventeen times, which reflects how much has been bolted onto it over the
engine's life.

Note the stub RVA `0x49265` is not 16-byte aligned and sits far into `.text`
rather than in the low-address registration block every other module uses. That is
consistent with the interface being registered late or through a different
mechanism than the standard bootstrap table.

## 4. Unknowns

1. `VFileSystem017` vtable not walked.
2. **What the socket is for** — the six imports are a raw TCP client (§1), but who
   connects the socket, and whether it carries remote content or something else,
   is not established. This is the highest-value unknown in the module.
3. The async completion thread model is not established.
4. VPK reading vs loose-file precedence order is not reversed.
