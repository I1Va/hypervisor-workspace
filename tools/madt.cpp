// Reports the ACPI processor topology exactly as Windows received it.
//
// Why this exists: the firmware's MP services report 4 enabled processors and
// the hypervisor virtualizes all 4, yet Windows creates exactly one processor
// object (only CentralProcessor\0 exists, WMI says NumberOfLogicalProcessors=1).
// Windows builds processor objects from the ACPI MADT, so "does Windows see 4
// processors or 1" must be read, not inferred.
//
// Method: EnumSystemFirmwareTables('ACPI') lists the table signatures the
// platform provides, and GetSystemFirmwareTable('ACPI', <sig>) returns each
// table's bytes. Reading each table by signature avoids guessing the layout of
// the concatenated blob.
//
// Reported per MADT:
//   - local APIC address and PC-AT compatibility flag
//   - every Processor Local APIC entry (type 0): ACPI id, APIC id, enabled
//   - every Processor Local x2APIC entry (type 9): APIC id, enabled
//   - interrupt source overrides (type 2), which reveal the 8259 vs APIC setup
//
// Build: cl /nologo /std:c++17 /EHsc /O1 madt.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#pragma pack(push, 1)
struct AcpiHeader
{
    char     Signature[4];
    uint32_t Length;
    uint8_t  Revision;
    uint8_t  Checksum;
    char     OemId[6];
    char     OemTableId[8];
    uint32_t OemRevision;
    char     CreatorId[4];
    uint32_t CreatorRevision;
};
#pragma pack(pop)

static uint32_t ReadU32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t ReadU64(const uint8_t* p) { uint64_t v; memcpy(&v, p, 8); return v; }

static std::vector<uint8_t> GetTable(DWORD sig)
{
    DWORD size = GetSystemFirmwareTable('ACPI', sig, nullptr, 0);
    if (size == 0) return {};

    std::vector<uint8_t> buf(size);
    DWORD got = GetSystemFirmwareTable('ACPI', sig, buf.data(), size);
    if (got == 0) return {};
    buf.resize(got);
    return buf;
}

static DWORD Sig(const char* s)
{
    return ((DWORD)(uint8_t)s[0]) | ((DWORD)(uint8_t)s[1] << 8) |
           ((DWORD)(uint8_t)s[2] << 16) | ((DWORD)(uint8_t)s[3] << 24);
}

int main()
{
    // 1. Which tables does the platform provide?
    DWORD listSize = EnumSystemFirmwareTables('ACPI', nullptr, 0);
    if (listSize == 0)
    {
        printf("EnumSystemFirmwareTables failed: %lu\n", GetLastError());
        return 1;
    }

    std::vector<DWORD> sigs(listSize / sizeof(DWORD));
    DWORD gotList = EnumSystemFirmwareTables('ACPI', sigs.data(), listSize);
    sigs.resize(gotList / sizeof(DWORD));

    printf("ACPI tables provided: %zu\n", sigs.size());
    for (DWORD s : sigs)
    {
        printf("  %.4s\n", (const char*)&s);
    }

    // 2. Dump the MADT (signature "APIC").
    printf("\n==== MADT ====\n");
    std::vector<uint8_t> madt = GetTable(Sig("APIC"));
    if (madt.size() < sizeof(AcpiHeader) + 8)
    {
        printf("no MADT returned (%zu bytes)\n", madt.size());
    }
    else
    {
        const AcpiHeader* h = (const AcpiHeader*)madt.data();
        printf("MADT len=%lu rev=%u oem=%.6s/%.8s\n",
               (unsigned long)h->Length, (unsigned)h->Revision,
               h->OemId, h->OemTableId);

        const uint8_t* base = madt.data();
        const uint32_t lapicAddress = ReadU32(base + 36);
        const uint32_t madtFlags    = ReadU32(base + 40);
        printf("local-apic-address=0x%08lX flags=0x%08lX (pc-at-compat=%u)\n",
               (unsigned long)lapicAddress, (unsigned long)madtFlags,
               (unsigned)(madtFlags & 1));

        const uint8_t* e    = base + 44;
        const uint8_t* mEnd = base + h->Length;

        int lapic = 0, lapicEnabled = 0, x2 = 0, x2Enabled = 0, overrides = 0, nmi = 0;

        while (e + 2 <= mEnd)
        {
            const uint8_t type = e[0];
            const uint8_t len  = e[1];
            if (len < 2 || e + len > mEnd) { printf("  malformed entry type=%u len=%u\n", type, len); break; }

            if (type == 0)
            {
                const uint8_t acpiId = e[2];
                const uint8_t apicId = e[3];
                const uint32_t flags = ReadU32(e + 4);
                ++lapic;
                if (flags & 1) ++lapicEnabled;
                printf("  LAPIC  acpi_id=%u apic_id=%u flags=0x%08lX %s\n",
                       (unsigned)acpiId, (unsigned)apicId, (unsigned long)flags,
                       (flags & 1) ? "ENABLED" : "DISABLED");
            }
            else if (type == 9)
            {
                const uint32_t apicId = ReadU32(e + 4);
                const uint32_t flags  = ReadU32(e + 8);
                ++x2;
                if (flags & 1) ++x2Enabled;
                printf("  X2APIC apic_id=%lu flags=0x%08lX %s\n",
                       (unsigned long)apicId, (unsigned long)flags,
                       (flags & 1) ? "ENABLED" : "DISABLED");
            }
            else if (type == 2)
            {
                const uint8_t bus = e[2], src = e[3];
                const uint32_t gsi = ReadU32(e + 4);
                const uint16_t flags = (uint16_t)(e[8] | (e[9] << 8));
                ++overrides;
                printf("  ISO    bus=%u src_irq=%u gsi=%lu flags=0x%04X\n",
                       (unsigned)bus, (unsigned)src, (unsigned long)gsi, flags);
            }
            else if (type == 1)
            {
                ++nmi;
                printf("  NMI    acpi_proc_id=%u flags=0x%04X lint=%u\n",
                       (unsigned)e[2], (unsigned)(e[3] | (e[4] << 8)), (unsigned)e[5]);
            }

            e += len;
        }

        printf("SUMMARY: lapic=%d enabled=%d x2apic=%d enabled=%d iso=%d nmi=%d\n",
               lapic, lapicEnabled, x2, x2Enabled, overrides, nmi);
    }

    // 3. What the kernel actually built.
    printf("\n==== KERNEL VIEW ====\n");
    printf("GetActiveProcessorCount(ALL)=%lu\n",
           (unsigned long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    printf("GetActiveProcessorGroupCount=%u\n",
           (unsigned)GetActiveProcessorGroupCount());
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    printf("GetSystemInfo.dwNumberOfProcessors=%lu\n", (unsigned long)si.dwNumberOfProcessors);

    // KUSER_SHARED_DATA is mapped read-only at a fixed address. The processor
    // count the kernel believes in is a DWORD near the end of the structure.
    const uint8_t* kusd = (const uint8_t*)0x7FFE0000;
    printf("KUSER_SHARED_DATA.ActiveProcessorCount(0x2D0)=%lu\n",
           (unsigned long)ReadU32(kusd + 0x2D0));

    // 4. The ACPI processor objects Windows created.
    printf("\n==== ACPI PROCESSOR OBJECTS ====\n");
    HKEY k;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "HARDWARE\\ACPI\\DSDT\\ACPI", 0, KEY_READ, &k) == ERROR_SUCCESS)
    {
        printf("HKLM\\HARDWARE\\ACPI\\DSDT\\ACPI exists\n");
        RegCloseKey(k);
    }
    else
    {
        printf("no DSDT\\ACPI key\n");
    }

    return 0;
}
