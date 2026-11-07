# `soundsystem.dll` — audio mixing and synthesis

Addresses are RVAs in `bin/win64/soundsystem.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **5,838,488** bytes |
| `SizeOfImage` | 7,053,312 (`0x6B9000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| PDB | `...\soundsystem\_vpc_soundsystem\default\win64\_msvc_\Retail\soundsystem.pdb` |
| `.pdata` records | 15,573 |
| Merged functions | **8,149** |
| Exports | **42** |
| Imports | `tier0` 311, `KERNEL32` 83, `WINMM` 1 |

42 exports — more than the six-symbol ABI, so it publishes a real audio API.

## 2. Interfaces registered — four

`CreateInterface` export at `0x3b8210`; stubs target thunk `0x3b81f0`.

| Interface | Stub RVA | Role |
|---|---|---|
| `SoundSystem001` | `0x49f5` | the mixer |
| `SoundOpSystem001` | `0xcda5` | sound **operators** at runtime |
| `SoundOpSystemEdit001` | `0x6d15` | the same, editor-side |
| `VMixEditTool001` | `0x5745` | the VMix authoring tool |

Four interfaces is notable, and the split is informative: `SoundOpSystem001` and
`SoundOpSystemEdit001` are **paired runtime/editor** variants of one interface, and
`VMixEditTool001` is a tooling interface. So this module serves both the game and
the audio-authoring tools, the same pattern as `helpsystem`'s Qt surface.

## 3. Synthesis — this is not just playback

The RTTI set shows a real synthesiser, not a sample player:

| Class | Role |
|---|---|
| `CAdditiveSynthInstanceView` | additive synthesis |
| `CAmpedDecaySineInstance` | a decaying sine generator |
| `CAudioCacheHandle`, `CAsyncWavDataCache` | async sample caching |
| `CAddonWatcher` | watches addon content for new/changed audio |
| `CAsyncProcessResult` | async processing result |

`CAdditiveSynthInstanceView` and `CAmpedDecaySineInstance` mean the engine
**generates** waveforms, not only mixes samples. That is how procedural sounds
(e.g. UI ticks, engine tones) are produced without shipping audio files.

`CAddonWatcher` is worth noting: it means audio content can change at runtime when
an addon changes, without a restart.

### libopus is statically linked

36 of the 42 exports are libopus:

```
opus_decode  opus_decode_float  opus_decoder_create  opus_encoder_create
opus_encode  opus_packet_parse  opus_repacketizer_*  opus_pcm_soft_clip
opus_get_version_string  ...
```

So OPUS is the voice codec, compiled in rather than loaded from a separate DLL.
`engine2.dll` also exports `opus_*` symbols, so libopus appears in **two** modules
— the same header/static-link duplication issue documented in `vphysics2.md`.

## 4. Wet/dry mixing

The `VMix` name (VMix, the Source 2 audio authoring tool) plus `VMixEditTool001`
means the signal graph is a **mix graph with operators** — the same model as a DAW
channel strip: sources feed operators (filters, reverb, ducking) in a graph that the
audio tool authors. `SoundOpSystem001` is that graph at runtime.

## 5. Unknowns

1. All four vtables not walked.
2. The mix-graph serialisation format is not reversed.
3. The 42 exports are 36 opus functions plus the module ABI — the opus set is named
   but not individually reversed.
4. Which audio output backend is used (WASAPI vs SDL3 vs direct) is not established —
   only `WINMM` (1 symbol) is imported, which suggests the real backend is
   elsewhere or dynamically loaded.
5. The synthesis DSP (which oscillator shapes exist) is not enumerated.
