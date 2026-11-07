# `schemasystem.dll` — Source 2 schema type system

Addresses are RVAs in `bin/win64/schemasystem.dll`, `ImageBase = 0x180000000`.

## 1. Identity

| Property | Value |
|---|---|
| Size on disk | **445,592** bytes |
| `SizeOfImage` | 520,192 (`0x7F000`) |
| SHA256 | `index/manifest.json` |
| ImageBase | `0x180000000` |
| Entry point | `0x39b3c` |
| Timestamp | 1793662325 |
| PDB | `...\schemasystem\_vpc_schemasystem\default\win64\_msvc_\Retail\schemasystem.pdb` |
| `.pdata` records | 1,397 |
| Merged functions | **635** |
| Exports | 6 (module ABI) |
| Imports | 3 DLLs, 156 symbols |

## 2. What it is

`schemasystem.dll` is the **runtime type system** that every Source 2 module
registers its types into. It is small (635 functions) because it is machinery, not
content: the schema *definitions* live in each module, and this module holds the
registry and the transfer (serialisation) framework over them.

Evidence — the RTTI set is nearly all transfer and registration:

| Class | Role |
|---|---|
| `CSchemaRegistration` | a registered type |
| `CKV3TransferContextBase`, `CKV3TransferSaveContext` | KeyValues3 serialisation context |
| `CExampleSchemaVData_PolymorphicBase` + `DerivedA` / `DerivedB` | a **test** polymorphic hierarchy compiled in |
| `CSchemaInstallCallback` | the module lifecycle hook that installs a module's schema |
| `CPostConnectCallback` | standard module callback |

The `CExampleSchemaVData_*` triple is notable: these are example/test types, and
their presence means the test schema classes ship in the retail binary. They are
harmless, but they are real symbols an attacker can key on.

## 3. Interface registered

`CreateInterface` export at `0x37560`; stubs target thunk `0x37540`. One:

| Interface | Stub RVA |
|---|---|
| `SchemaSystem_001` | `0x1085` |

`SchemaSystem_001` is held by every module during `InstallSchemaBindings` — it is
one of the six module-ABI exports, so the dependency is circular by design: a
module is handed `SchemaSystem_001` in order to register the very types that
`SchemaSystem_001` will then describe.

## 4. Why this module matters for the hypervisor work

Every module's `InstallSchemaBindings` export (present in the 24 Valve modules
that publish the standard six-symbol ABI) runs
through this interface. That makes `SchemaSystem_001` a single choke point through
which all type registration passes — useful for understanding the binary's
structure, and a single point that a tool inspecting loaded modules could observe.

## 5. Unknowns

1. `SchemaSystem_001` vtable not walked.
2. The KV3 transfer wire format is not reversed (only the context classes are
   identified).
3. How type identity is computed (hash of name? assigned ID?) is not established.
4. The test hierarchy's registration path is not traced.
