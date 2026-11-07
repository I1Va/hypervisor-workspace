# `video64.dll` — video decode, encode and streaming

Addresses are RVAs in `bin/win64/video64.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **4,610,448** bytes |
| `SizeOfImage` | 5,857,280 (`0x596000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `c:\buildslave\steam_main_win64\build\src\common\video\win64\videoRelease\video64.pdb` |
| `.pdata` records | 11,966 |
| Merged functions | **7,721** |
| Exports | **57** |
| Interfaces | **0** |

### This is not a CS2 module

Two facts separate it from every other Valve module here:

1. **The PDB path is different.** Every other module builds from
   `C:\buildworker\csgo_rel_win64\...`. This one builds from
   `c:\buildslave\steam_main_win64\build\src\common\video\` — a **Steam client**
   build tree, not the CS2 tree. It is a shared Steam component shipped into the
   game folder.
2. **It registers no interfaces**, and it has 57 real exports rather than the
   standard six-symbol module ABI. It is a plain DLL with a C-style API, not a
   Source 2 module.

Note that `SizeOfImage` (5,857,280 = `0x596000`) is **identical** to `vphysics2`'s.
That is not a shared dependency: both binaries happen to end just below the same
1 MB-aligned round-up, and both carry the same trailing `_RDATA` linker artifact
(`video64` last section ends at `0x59590c`, `vphysics2` at `0x5953a0`, and both
round to `0x596000`).

## 2. What it does — the export surface

The 57 exports are a complete media toolkit:

**Playback**

```
CreateVideoPlayer   DeleteVideoPlayer   VideoPlaybackInitialize
VideoPauseForValidation
```

**Decode / encode**

```
CreateVideoDecoder  DeleteVideoDecoder
CreateVideoEncoder  DeleteVideoEncoder
CreateAudioFileDecoder  DeleteAudioFileDecoder
CreateAudioResampler    DeleteAudioResampler
```

**Format conversion and scaling**

```
AllocImageYUV   FreeImageYUV   ValidateImageYUV   BConvertYUVtoRGB
BScaleImageYUV  BScaleImageNV12   RescaleBase
```

**Live streaming**

```
CreateRTMPStream   DeleteRTMPStream
```

`CreateRTMPStream` is the notable one: RTMP is the protocol used to stream to
Twitch and YouTube. The game can **publish a live stream**, and the RTMP client is
compiled in.

## 3. Dependencies

| DLL | Symbols | Note |
|---|---|---|
| `KERNEL32` | 178 | |
| `USER32` | 25 | |
| `WS2_32` | 28 | **sockets** — for RTMP |
| `libavcodec-58` | 12 | FFmpeg decode/encode |
| `libavformat-58` | 16 | FFmpeg container/stream |
| `libavutil-56` | 17 | FFmpeg helpers |
| `libavresample-4` | 6 | FFmpeg resampling |
| `libswscale-5` | 3 | FFmpeg pixel scaling |
| `CRYPT32`, `bcrypt` | 7, 1 | TLS for the stream |
| `WSOCK32` | 1 | legacy |
| `PSAPI`, `VERSION`, `SHELL32`, `OLEAUT32`, `ADVAPI32` | few | incidental |

The FFmpeg split across five DLLs is the standard ffmpeg shared-library layout. The
module is a **thin wrapper**: it owns the player/streamer lifecycle and hands the
actual codec work to FFmpeg. That explains 7,721 functions for what looks like
wrapper code — much of it is the inlined glue and state machines, not codecs.

`CRYPT32` + `bcrypt` + `WS2_32` together with RTMP means the stream is
authenticated/encrypted over the network.

## 4. Why it matters

For a test stand: this module opens **outbound network connections** when a stream
is started, which is a distinct behaviour class from anything else in the CS2
corpus. Nothing here executes unless video playback or streaming is started.

## 5. Unknowns

1. Which codecs are enabled (FFmpeg is built with a configure-time subset).
2. Whether the RTMP path is reachable from the game UI or only from the SDK.
3. The player/streamer object layout.
4. Whether `VideoPauseForValidation` is a test hook or a real feature.
