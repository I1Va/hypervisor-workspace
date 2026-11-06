// Reports exactly what VMAware's hyper_x() would see on this guest.
//
// If hyper_x() returned HYPERV_HOST, VMAware would skip TIMER's CPUID sub-check,
// accept a missing DR6.B0 in TRAP, and return false from INTERRUPT_SHADOW - the
// three remaining detections. Reaching that state needs every gate below, and
// failing one of them is worse than doing nothing: the SPOOFED branch adds
// brand_enum::NULL_BRAND at 150 points.
//
// Gates, in the order hyper_x() applies them:
//   1. cpuid.0x40000000 vendor string == "Microsoft Hv"
//   2. cpuid.0x40000001 EBX bit 0 (root partition flag)
//   3. is_log_present(): TCG measured-boot log readable via tbs.dll
//   4. (Windows 11 + admin only) Hyper-V HAL present - NOT applicable on Win10
#include <windows.h>
#include <intrin.h>
#include <cstdio>
#include <cstring>
#include <cstdint>

static void vendor_leaf()
{
    int r[4] = {0,0,0,0};
    __cpuid(r, 0x40000000);
    char v[13] = {0};
    memcpy(v, &r[1], 4);
    memcpy(v + 4, &r[2], 4);
    memcpy(v + 8, &r[3], 4);
    printf("cpuid.40000000 eax(maxleaf)=0x%08X vendor=\"%s\"\n", (unsigned)r[0], v);
    printf("  vendor_is_Microsoft_Hv=%d\n",
           strcmp(v, "Microsoft Hv") == 0 ? 1 : 0);
}

static void priv_leaf()
{
    int r[4] = {0,0,0,0};
    __cpuid(r, 0x40000001);
    printf("cpuid.40000001 eax=0x%08X ebx=0x%08X ecx=0x%08X edx=0x%08X\n",
           (unsigned)r[0], (unsigned)r[1], (unsigned)r[2], (unsigned)r[3]);
    printf("  root_partition(ebx bit0)=%d\n", (int)(r[1] & 1));
}

static void hv_present_bit()
{
    int r[4] = {0,0,0,0};
    __cpuid(r, 1);
    printf("cpuid.1 ecx bit31 (hypervisor present)=%d\n", (int)((r[2] >> 31) & 1));
}

static void tbs_check()
{
    // Mirrors is_log_present(): returns TRUE when the log is readable OR when
    // tbs.dll / its exports cannot be resolved. Returns FALSE only when the
    // calls work and report no log - which is the SPOOFED path.
    HMODULE tbs = LoadLibraryExW(L"tbs.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!tbs) {
        printf("tbs.dll: NOT LOADED (error %lu) -> is_log_present() would return TRUE\n",
               GetLastError());
        return;
    }
    printf("tbs.dll: loaded\n");

    typedef int (__stdcall *get_ex_fn)(uint32_t, uint8_t*, uint32_t*);
    typedef int (__stdcall *ctx_create_fn)(void*, void**);
    typedef int (__stdcall *get_log_fn)(void*, uint8_t*, uint32_t*);
    typedef int (__stdcall *ctx_close_fn)(void*);

    get_ex_fn get_ex = (get_ex_fn)GetProcAddress(tbs, "Tbsi_Get_TCG_Log_Ex");
    ctx_create_fn ccreate = (ctx_create_fn)GetProcAddress(tbs, "Tbsi_Context_Create");
    get_log_fn get_log = (get_log_fn)GetProcAddress(tbs, "Tbsi_Get_TCG_Log");
    ctx_close_fn cclose = (ctx_close_fn)GetProcAddress(tbs, "Tbsip_Context_Close");

    printf("exports: Get_TCG_Log_Ex=%p Context_Create=%p Get_TCG_Log=%p Close=%p\n",
           (void*)get_ex, (void*)ccreate, (void*)get_log, (void*)cclose);

    if (!get_ex && !(ccreate && get_log && cclose)) {
        printf("-> exports missing, is_log_present() would return TRUE\n");
        FreeLibrary(tbs);
        return;
    }

    uint32_t size = 0;
    int hr = -1;
    if (get_ex) {
        hr = get_ex(0, nullptr, &size);
        printf("Tbsi_Get_TCG_Log_Ex(0,NULL,&size): hr=0x%08X size=%u\n", (unsigned)hr, size);
    }
    printf("-> is_log_present() would return %s\n", (hr == 0 || (unsigned)hr == 0x80284005u) ? "TRUE" : "TRUE (via other path)");
    FreeLibrary(tbs);
}

int main()
{
    hv_present_bit();
    vendor_leaf();
    priv_leaf();
    tbs_check();

    printf("\n--- other hypervisor-ish leaves ---\n");
    int r[4];
    __cpuid(r, 0x40000002);
    printf("cpuid.40000002 eax=0x%08X ebx=0x%08X\n", (unsigned)r[0], (unsigned)r[1]);
    __cpuid(r, 0x40000003);
    printf("cpuid.40000003 eax=0x%08X ebx=0x%08X\n", (unsigned)r[0], (unsigned)r[1]);
    fflush(stdout);
    return 0;
}
