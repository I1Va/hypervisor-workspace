#!/usr/bin/env python3
"""Parse the embedded FileDescriptorProto blobs fully: messages, fields,
field numbers, and types. This is the authoritative wire schema."""
import net, json

m = net.Mod()
D = m.data

def rv(b, i):
    r = 0; s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7f) << s
        if not (x & 0x80): return r, i
        s += 7

def fields(b, i, end):
    while i < end:
        key, i = rv(b, i)
        fn, wt = key >> 3, key & 7
        if wt == 0:
            v, i = rv(b, i); yield fn, wt, v
        elif wt == 2:
            ln, i = rv(b, i); yield fn, wt, b[i:i+ln]; i += ln
        elif wt == 1:
            yield fn, wt, b[i:i+8]; i += 8
        elif wt == 5:
            yield fn, wt, b[i:i+4]; i += 4
        else:
            return

TYPES = {1:'double',2:'float',3:'int64',4:'uint64',5:'int32',8:'bool',9:'string',
         10:'group',11:'message',12:'bytes',13:'uint32',14:'enum',15:'sfixed32',
         16:'sfixed64',17:'sint32',18:'sint64'}

def parse_field(b):
    name = None; num = None; typ = None; tname = None; label = None
    for fn, wt, v in fields(b, 0, len(b)):
        if fn == 1 and wt == 2: name = v.decode('utf-8','replace')
        elif fn == 3 and wt == 0: num = v
        elif fn == 4 and wt == 0: label = v
        elif fn == 5 and wt == 0: typ = v
        elif fn == 6 and wt == 2: tname = v.decode('utf-8','replace')
    return {'name': name, 'num': num, 'type': TYPES.get(typ, typ), 'type_name': tname,
            'label': label}

def parse_msg(b):
    name = None; fs = []
    for fn, wt, v in fields(b, 0, len(b)):
        if fn == 1 and wt == 2: name = v.decode('utf-8','replace')
        elif fn == 2 and wt == 2: fs.append(parse_field(v))
    return {'name': name, 'fields': fs}

def find_fdps():
    """A FileDescriptorProto is a run of field1(name)/field2(package)/field4(message_type)/
    field5(enum_type)/field12(syntax). Find starts by scanning for field-12 'proto2'/'proto3'
    and walking back is hard; instead scan every offset that parses as a full FDP with a
    plausible name and >=1 message."""
    out = []
    n = len(D)
    # candidate starts: bytes 0x0a <len> then a name ending in .proto
    for i in range(n - 16):
        if D[i] != 0x0a: continue
        try:
            ln, j = rv(D, i+1)
        except Exception:
            continue
        if not (5 <= ln <= 80) or j+ln >= n: continue
        nm = D[j:j+ln]
        if not nm.endswith(b'.proto'): continue
        if not all(32 < c < 127 for c in nm): continue
        # try parsing forward with increasing end, accept the longest valid parse
        best = None
        for extra in range(64, 400000, 4):
            end = j+ln+extra
            if end > n: break
            try:
                msg = parse_msg_proto(D[i:end])
            except Exception:
                continue
            if msg and len(msg['fields']) >= 2:
                best = (end, msg)
        if best:
            out.append((i, best[0], best[1]))
    return out

def parse_msg_proto(b):
    """parse a whole FileDescriptorProto; require strict consumption"""
    try:
        i = 0; end = len(b)
        res = {'name': None, 'package': None, 'messages': [], 'enums': []}
        while i < end:
            key, i = rv(b, i)
            fn, wt = key >> 3, key & 7
            if wt == 0:
                v, i = rv(b, i)
            elif wt == 2:
                ln, i = rv(b, i)
                v = b[i:i+ln]; i += ln
                if i > end: return None
                if fn == 1: res['name'] = v.decode('utf-8','replace')
                elif fn == 2: res['package'] = v.decode('utf-8','replace')
                elif fn == 4: res['messages'].append(parse_msg(v))
                elif fn == 5: pass
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                return None
            if i > end: return None
        if i != end: return None
        return res
    except Exception:
        return None

if __name__ == '__main__':
    # The descriptor blob is contiguous in .rdata. Find the big message table by
    # locating known message names and parsing the enclosing FDP.
    import sys
    # manual: the netmessages.proto blob starts near 0x221212 ("netmessages.proto")
    # Parse from a candidate start: walk back to the 0x0a tag.
    anchor = 0x221212
    o = m.rva2off(anchor)
    start = o - 2   # 0x0a <len>
    # find real start by scanning back for 0x0a with matching length
    for back in range(0, 200):
        s = o - back - 2
        if s < 0: break
        if D[s] != 0x0a: continue
        try:
            ln, j = rv(D, s+1)
        except Exception:
            continue
        if j + ln == o + 11:  # len of 'netmessages.proto'
            start = s
            break
    print('blob start off', hex(start), 'rva', hex(m.off2rva(start)))
    # parse greedily
    msg = parse_msg_proto(D[start:start+200000])
    print('parsed:', bool(msg))
    if msg:
        print('name', msg['name'], 'package', msg['package'], 'msgs', len(msg['messages']))
        for mm in msg['messages']:
            print('==', mm['name'], len(mm['fields']))
