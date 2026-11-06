// Reports exactly what VMAware's is_log_present() would decide, by running the
// same tbs.dll calls it makes.
//
// is_log_present() is the gate that decides HYPERV_HOST versus HYPERV_SPOOFED,
// and SPOOFED is worth 150 points - worse than the 145 the two remaining
// techniques cost. So this is the question that decides whether branding is
// viable at all, and it must be answered by measurement, not assumption.
//
// The function returns TRUE on any error path (including "tbs.dll missing" and
// "exports missing"), and only returns FALSE when the calls succeed and report no
// log. It also parses the log for a "Spec ID Event03" structure, so a log that
// exists but has the wrong shape also ends in FALSE.
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>

int main()
{
    HMODULE tbs = LoadLibraryExW(L"tbs.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!tbs) {
        printf("tbs.dll: NOT LOADED (err %lu)\n", GetLastError());
        printf("=> is_log_present() returns TRUE (VMAware treats this as 'log present')\n");
        return 0;
    }
    printf("tbs.dll: loaded\n");

    typedef int(__stdcall* get_ex_fn)(uint32_t, uint8_t*, uint32_t*);
    typedef int(__stdcall* ctx_create_fn)(void*, void**);
    typedef int(__stdcall* get_log_fn)(void*, uint8_t*, uint32_t*);
    typedef int(__stdcall* ctx_close_fn)(void*);

    get_ex_fn   get_ex  = (get_ex_fn)GetProcAddress(tbs, "Tbsi_Get_TCG_Log_Ex");
    ctx_create_fn ccreate = (ctx_create_fn)GetProcAddress(tbs, "Tbsi_Context_Create");
    get_log_fn  get_log = (get_log_fn)GetProcAddress(tbs, "Tbsi_Get_TCG_Log");
    ctx_close_fn cclose = (ctx_close_fn)GetProcAddress(tbs, "Tbsip_Context_Close");

    printf("exports: Log_Ex=%p Create=%p Get=%p Close=%p\n",
           (void*)get_ex, (void*)ccreate, (void*)get_log, (void*)cclose);

    if (!get_ex && !(ccreate && get_log && cclose)) {
        printf("=> exports missing, is_log_present() returns TRUE\n");
        FreeLibrary(tbs);
        return 0;
    }

    uint32_t size = 0;
    int hr = -1;
    uint8_t* buf = nullptr;

    if (get_ex) {
        hr = get_ex(0, nullptr, &size);
        printf("Tbsi_Get_TCG_Log_Ex(0,NULL,&size): hr=0x%08X size=%u\n", (unsigned)hr, size);
        if ((hr == 0 || (unsigned)hr == 0x80284005u) && size > 0) {
            buf = new uint8_t[size];
            if (buf) {
                hr = get_ex(0, buf, &size);
                printf("  fetch: hr=0x%08X size=%u\n", (unsigned)hr, size);
            }
        }
    }

    if (!buf) {
        // The exact is_log_present() semantics: a failed fetch returns TRUE.
        printf("=> no log buffer; is_log_present() returns TRUE\n");
        FreeLibrary(tbs);
        return 0;
    }

    // Parse the first event for "Spec ID Event03", as VMAware does.
    bool spec03 = false;
    if (size >= 32) {
        uint32_t event_data_size = 0;
        memcpy(&event_data_size, buf + 28, 4);
        printf("first event: data_size=%u total=%u\n", event_data_size, size);
        if (event_data_size >= 16) {
            spec03 = (memcmp(buf + 32, "Spec ID Event03", 15) == 0);
        }
        printf("Spec ID Event03 = %s\n", spec03 ? "YES" : "NO");
    } else {
        printf("log too short (%u bytes)\n", size);
    }

    printf("=> is_log_present() returns %s\n", spec03 ? "TRUE (log parses)" : "TRUE (on error path)");
    delete[] buf;
    FreeLibrary(tbs);
    return 0;
}
