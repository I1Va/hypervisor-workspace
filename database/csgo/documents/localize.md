# `localize.dll` — localisation engine

Addresses are RVAs in `bin/win64/localize.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **382,104** bytes |
| `SizeOfImage` | 389,120 (`0x5F000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0x31c2c` |
| Timestamp | 1793662271 |
| PDB | `...\localize\_vpc_localize\default\win64\_msvc_\Retail\localize.pdb` |
| `.pdata` records | 1,167 |
| Merged functions | **509** |
| Exports | 6 (module ABI) |
| Imports | 3 DLLs, 188 symbols |

## 2. What it is

The localisation engine: it resolves `#Token` references to translated strings and
parses the token syntax that allows grammatical variation.

The RTTI set is small (40) but unusually specific — it is a **parser**:

| Class | Role |
|---|---|
| `CLocVariableSet`, `CLocVariableSetBase` | the set of variables a token can reference |
| `CLocalizationEngineParseNode` | a node in the parsed token tree |
| `..._GenderSelector`, `..._PluralSelector`, `..._StringSelector` | conditional variants |
| `CAssertErrorListener` | parse-error reporting |

This is the important part: `localize` is not a flat string table. The
`GenderSelector`/`PluralSelector` nodes mean a single token can resolve differently
by grammatical gender and plural count — a full ICU-style conditional
implementation, in ~500 functions.

## 3. Interface registered

`CreateInterface` export at `0x30900`; stubs target thunk `0x308e0`. One:

| Interface | Stub RVA |
|---|---|
| `Localize_001` | `0x1075` |

## 4. Design note

`CLocalizationEngineParseNode` having a `_SelectorBase` base class means the
selector variants are polymorphic, resolved at parse time rather than at lookup.
That is the right design for a system evaluated per-frame per-string: parse once,
then walk a prepared tree.

## 5. Unknowns

1. `Localize_001` vtable not walked.
2. The token syntax grammar is not extracted (the parse nodes exist, but their
   production rules are not reversed).
3. Whether translations are compiled into `.vpk` files or loaded from the
   filesystem is not established; `filesystem_stdio`/`resourcesystem` integration
   is not traced.
4. The 188 imported symbols were not classified.
