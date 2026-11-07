#!/usr/bin/env python3
"""Leaf-aware function sizing: for an address that is not a .pdata entry, find
the true end by scanning forward for `ret` followed by int3 padding."""
import bisect
from srv import Mod

m = Mod()
F = m.funcs()
KS = sorted(F)


def end_of(rva, limit=0x2000):
    if rva in F:
        return rva + F[rva]
    o = m.rva2off(rva)
    if o is None:
        return rva
    d = m.data
    # next known entry
    i = bisect.bisect_right(KS, rva)
    nxt = KS[i] if i < len(KS) else rva + limit
    # scan for c3 / c2 followed by int3 or next entry
    j = o
    end = o + min(limit, nxt - rva)
    while j < end:
        b = d[j]
        if b == 0xC3:  # ret
            k = j + 1
            while k < end and d[k] == 0xCC:
                k += 1
            if k >= end or d[k] != 0xCC:
                return m.off2rva(j) + 1
        j += 1
    return nxt


def size(rva):
    return end_of(rva) - rva


if __name__ == '__main__':
    import sys
    for a in sys.argv[1:]:
        r = int(a, 16)
        print(hex(r), hex(size(r)))
