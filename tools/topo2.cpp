// Reports the processor topology exactly as GetLogicalProcessorInformationEx
// returns it, which is what VMAware's TIMER technique consumes.
//
// Why this matters: TIMER needs two *different physical cores* - one thread to
// raise an exception, another to measure instruction latency. Its scheduler
// (timer::scheduler::get_mask) reads RelationProcessorCore and explicitly
// excludes SMT siblings, and refuses to run unless it can find at least two
// distinct cores. That data comes from CPUID topology leaves, surfaced by the
// kernel through this API.
//
// If the topology Windows derived is inconsistent - for example every logical
// processor claiming to be core 0, or the SMT/core flags contradicting the
// processor count - the scheduler can pin both threads to the same core. TIMER
// spin-waits between them, so that deadlocks the guest rather than failing.
//
// Reported:
//   - RelationProcessorCore: one record per physical core, with the logical
//     processor mask(s) it owns, SMT flag, and efficiency class
//   - RelationCache: L1/L2/L3 groups, to show cache sharing
//   - RelationNumaNode
//   - CPUID leaf 0xB / 0x1F topology, to compare against the above
//   - CPUID leaf 4 EAX[31:26] core count, the older way to read it
//
// Build: cl /nologo /std:c++17 /EHsc /O1 topo2.cpp
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <intrin.h>
#include <vector>

static void Cpuid(unsigned leaf, unsigned sub, unsigned out[4])
{
    int r[4];
    __cpuidex(r, (int)leaf, (int)sub);
    out[0] = (unsigned)r[0]; out[1] = (unsigned)r[1];
    out[2] = (unsigned)r[2]; out[3] = (unsigned)r[3];
}

static int Popcount(KAFFINITY m)
{
    int n = 0;
    for (int i = 0; i < (int)(sizeof(KAFFINITY) * 8); ++i) {
        if (m & ((KAFFINITY)1 << i)) ++n;
    }
    return n;
}

int main()
{
    printf("=== CPUID topology ===\n");
    unsigned r[4];
    Cpuid(0, 0, r);
    const unsigned maxLeaf = r[0];
    printf("max basic leaf = %u\n", maxLeaf);

    unsigned coresPerPkg = 0, logicalPerPkg = 0;
    // Leaf 4 (deterministic cache params) EAX[31:26] = max cores in package.
    if (maxLeaf >= 4) {
        Cpuid(4, 0, r);
        coresPerPkg = (r[0] >> 26) & 0x3F;
    }

    // Leaf 0xB enumerates topology; count the SMT and core levels.
    if (maxLeaf >= 0xB) {
        for (unsigned sub = 0; ; ++sub) {
            Cpuid(0xB, sub, r);
            const unsigned levelType = (r[2] >> 8) & 0xFF;
            const unsigned count = r[1] & 0xFFFF;
            if (levelType == 0 && count == 0) break;
            printf("leaf 0xB sub %u: type=%u count=%u shift=%u\n",
                   sub, levelType, count, r[0] & 0x1F);
            if (levelType == 1) logicalPerPkg = count;   // SMT level
            if (levelType == 2) coresPerPkg = count;     // core level
            if (sub > 8) break;
        }
    }
    printf("coresPerPkg(leaf4)=%u coresPerPkg(leafB)=%u logicalPerPkg(leafB)=%u\n",
           coresPerPkg, coresPerPkg, logicalPerPkg);

    printf("\n=== RelationProcessorCore ===\n");
    DWORD len = 0;
    if (GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &len) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("size query failed: %lu\n", GetLastError());
        return 1;
    }

    std::vector<unsigned char> buf(len);
    if (!GetLogicalProcessorInformationEx(RelationProcessorCore,
            (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)buf.data(), &len)) {
        printf("query failed: %lu\n", GetLastError());
        return 1;
    }

    int coreIndex = 0, totalLogical = 0;
    for (DWORD off = 0; off < len; ) {
        auto* rec = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(buf.data() + off);
        if (rec->Size == 0) break;

        if (rec->Relationship == RelationProcessorCore) {
            const PROCESSOR_RELATIONSHIP& pr = rec->Processor;
            printf("core %d: GroupCount=%u Flags=0x%X EfficiencyClass=%u",
                   coreIndex, (unsigned)pr.GroupCount, (unsigned)pr.Flags,
                   (unsigned)pr.EfficiencyClass);
            for (WORD g = 0; g < pr.GroupCount; ++g) {
                printf("  group=%u mask=0x%llX (%d logical)",
                       (unsigned)pr.GroupMask[g].Group,
                       (unsigned long long)pr.GroupMask[g].Mask,
                       Popcount(pr.GroupMask[g].Mask));
                totalLogical += Popcount(pr.GroupMask[g].Mask);
            }
            printf("%s\n", (pr.Flags & LTP_PC_SMT) ? "  [SMT]" : "");
            ++coreIndex;
        }
        off += rec->Size;
    }
    printf("physical cores = %d, total logical = %d\n", coreIndex, totalLogical);

    printf("\n=== RelationCache ===\n");
    DWORD clen = 0;
    if (GetLogicalProcessorInformationEx(RelationCache, nullptr, &clen) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("cache size query failed: %lu\n", GetLastError());
    } else {
        std::vector<unsigned char> cbuf(clen);
        if (GetLogicalProcessorInformationEx(RelationCache,
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)cbuf.data(), &clen)) {
            for (DWORD off = 0; off < clen; ) {
                auto* rec = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(cbuf.data() + off);
                if (rec->Size == 0) break;
                if (rec->Relationship == RelationCache) {
                    const CACHE_RELATIONSHIP& cr = rec->Cache;
                    printf("cache level=%u assoc=0x%X line=%u size=%luKB type=%u ",
                           (unsigned)cr.Level, (unsigned)cr.Associativity,
                           (unsigned)cr.LineSize, (unsigned long)(cr.CacheSize / 1024),
                           (unsigned)cr.Type);
                    printf("group=%u mask=0x%llX (%d logical)\n",
                           (unsigned)cr.GroupMask.Group,
                           (unsigned long long)cr.GroupMask.Mask,
                           Popcount(cr.GroupMask.Mask));
                }
                off += rec->Size;
            }
        }
    }

    printf("\n=== NUMA ===\n");
    DWORD nlen = 0;
    if (GetLogicalProcessorInformationEx(RelationNumaNode, nullptr, &nlen) ||
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        printf("numa size query failed: %lu\n", GetLastError());
    } else {
        std::vector<unsigned char> nbuf(nlen);
        if (GetLogicalProcessorInformationEx(RelationNumaNode,
                (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)nbuf.data(), &nlen)) {
            int nodes = 0;
            for (DWORD off = 0; off < nlen; ) {
                auto* rec = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX)(nbuf.data() + off);
                if (rec->Size == 0) break;
                if (rec->Relationship == RelationNumaNode) {
                    const NUMA_NODE_RELATIONSHIP& nr = rec->NumaNode;
                    printf("numa node %lu group=%u mask=0x%llX (%d logical)\n",
                           (unsigned long)nr.NodeNumber,
                           (unsigned)nr.GroupMask.Group,
                           (unsigned long long)nr.GroupMask.Mask,
                           Popcount(nr.GroupMask.Mask));
                    ++nodes;
                }
                off += rec->Size;
            }
            printf("numa nodes = %d\n", nodes);
        }
    }

    printf("\n=== kernel view ===\n");
    printf("GetActiveProcessorCount(ALL) = %lu\n",
           (unsigned long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    printf("GetActiveProcessorGroupCount = %u\n", (unsigned)GetActiveProcessorGroupCount());

    printf("\nVERDICT: %s\n",
        (coreIndex == 4 && totalLogical == 4)
            ? "coherent: 4 physical cores, 4 logical processors, no SMT"
            : "INCONSISTENT topology - TIMER's two-core scheduler will misbehave");
    return 0;
}
