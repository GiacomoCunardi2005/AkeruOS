#!/usr/bin/env python3
"""Analyze the DSPT table written by AkeruOS/nikon_v11_memdump_worker_dsptest.c (read-only).

Usage: s33_dsptest_analyze.py DSPTEST.BIN [out.json]   |   s33_dsptest_analyze.py --selftest
"""
import json, struct, sys

MAGIC, END, MAX = 0x54505344, 0x444E4554, 640
M = 0xFFFFFFFF
EDGES = [0, 1, 2, 0x7FFF, 0x8000, 0xFFFF, 0x10000, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF, 0x12345678]
OPS = ('muldw', 'muludw', 'macdw', 'macudw')


def expected_inputs():
    """(tag, mode, b, c) in the exact order of dsp_probe(); tag low bits = op."""
    seq, x = [], 0x533D0001
    def lcg():
        nonlocal x
        x = (x * 1664525 + 1013904223) & M
        return x
    for b in EDGES:
        for c in EDGES:
            for op in (0, 1): seq.append((0x000 | op, 0, b, c))
    for b in EDGES[:8]:
        for c in EDGES[:8]:
            for op in (0, 1): seq.append((0x100 | op, 8, b, c))
    for _ in range(32):
        b, c = lcg(), lcg()
        for op in (0, 1): seq.append((0x200 | op, 0, b, c))
    for i in range(64):
        s = i & 1
        b, c, b2, c2 = lcg(), lcg(), lcg(), lcg()
        seq += [(0x300 | s, 0, b, c), (0x300 | (2 + s), 0, b2, c2)]
    assert len(seq) == 608 <= MAX
    return seq


def s16(v):
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


def lanes(op, b, c):
    """Hypothesis H1: r56 = high-lane product, r57 = low-lane product (signed for muldw/macdw)."""
    f = s16 if op in (0, 2) else (lambda v: v & 0xFFFF)
    return (f(b >> 16) * f(c >> 16)) & M, (f(b) * f(c)) & M


def find_table(data):
    hits = []
    key = struct.pack('<II', MAGIC, 1)
    pos = data.find(key)
    while pos >= 0:
        if pos % 4 == 0 and pos + 16 + MAX * 24 + 4 <= len(data):
            count = struct.unpack_from('<I', data, pos + 8)[0]
            if count == 608 and struct.unpack_from('<I', data, pos + 16 + MAX * 24)[0] == END:
                hits.append(pos)
        pos = data.find(key, pos + 1)
    return hits


def analyze(data):
    hits = find_table(data)
    if len(hits) != 1:
        return {'status': 'TABLE_NOT_FOUND' if not hits else 'TABLE_AMBIGUOUS', 'offsets': [hex(h) for h in hits]}
    base = hits[0]
    saved_mode = struct.unpack_from('<I', data, base + 12)[0]
    recs = [struct.unpack_from('<6I', data, base + 16 + 24 * i) for i in range(608)]
    exp = expected_inputs()
    bad_inputs = [i for i, (r, e) in enumerate(zip(recs, exp)) if (r[0], r[1], r[2], r[3]) != e]
    cats = {}
    def add(cat, ok, rec):
        d = cats.setdefault(cat, {'match': 0, 'total': 0, 'first_mismatches': []})
        d['total'] += 1; d['match'] += ok
        if not ok and len(d['first_mismatches']) < 8:
            d['first_mismatches'].append({k: hex(v) for k, v in zip(('tag', 'mode', 'b', 'c', 'r56', 'r57'), rec)})
    mode0 = {}
    for i, r in enumerate(recs):
        tag, mode, b, c, h, l = r
        op, grp = tag & 3, tag & ~3
        if grp in (0x000, 0x200):
            add(f'{OPS[op]}_mode0', lanes(op, b, c) == (h, l), r)
            mode0[(op, b, c)] = (h, l)
            if grp == 0x000:
                add(f'{OPS[op]}_mode0_r57_only', lanes(op, b, c)[1] == l, r)
        elif grp == 0x100:
            add(f'{OPS[op]}_mode8_equals_mode0', mode0.get((op, b, c)) == (h, l), r)
            add(f'{OPS[op]}_mode8_equals_H1', lanes(op, b, c) == (h, l), r)
        elif op >= 2:
            ph, pl = recs[i - 1][4], recs[i - 1][5]
            eh, el = lanes(op, b, c)
            add(f'{OPS[op]}_accumulate', ((ph + eh) & M, (pl + el) & M) == (h, l), r)
        else:
            add(f'{OPS[op]}_seed', lanes(op, b, c) == (h, l), r)
    return {'status': 'OK' if not bad_inputs else 'INPUTS_CORRUPT', 'table_offset': hex(base),
            'saved_macmode': hex(saved_mode), 'input_mismatches': len(bad_inputs), 'categories': cats}


def synth(model):
    t = bytearray(struct.pack('<4I', MAGIC, 1, 608, 0))
    prev = (0, 0)
    for tag, mode, b, c in expected_inputs():
        h, l = model(tag & 3, b, c)
        if tag & 3 >= 2: h, l = (prev[0] + h) & M, (prev[1] + l) & M
        prev = (h, l)
        t += struct.pack('<6I', tag, mode, b, c, h, l)
    t += bytes(24 * (MAX - 608)) + struct.pack('<I', END)
    return bytes(64) + t + bytes(64)


def selftest():
    ok = analyze(synth(lanes))
    assert ok['status'] == 'OK' and all(d['match'] == d['total'] for d in ok['categories'].values()), ok
    swapped = analyze(synth(lambda op, b, c: lanes(op, b, c)[::-1]))
    assert swapped['categories']['muldw_mode0']['match'] < swapped['categories']['muldw_mode0']['total']
    unsigned_only = analyze(synth(lambda op, b, c: lanes(op | 1, b, c)))
    assert unsigned_only['categories']['muldw_mode0']['match'] < unsigned_only['categories']['muldw_mode0']['total']
    assert analyze(bytes(4096))['status'] == 'TABLE_NOT_FOUND'
    print('SELFTEST PASS')


if __name__ == '__main__':
    if sys.argv[1:] == ['--selftest']:
        selftest()
    else:
        rep = analyze(open(sys.argv[1], 'rb').read())
        text = json.dumps(rep, indent=1)
        if len(sys.argv) > 2: open(sys.argv[2], 'w').write(text + '\n')
        print(rep['status'], rep.get('table_offset'), rep.get('saved_macmode'))
        for k, d in rep.get('categories', {}).items(): print(f"  {k:28s} {d['match']}/{d['total']}")
