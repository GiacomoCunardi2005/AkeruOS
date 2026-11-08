#!/usr/bin/env python3
"""Static census of muldw/muludw/mulrdw in verified block 0 (read-only, no CPU semantics)."""
import collections, json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, disasm

OUT = ROOT / 'Risultati/Analisi_Statica/Muldw_Census_20261108'

def rows_of(text):
    for l in text.splitlines():
        p = l.split('\t')
        if len(p) >= 3 and re.match(r'\s*[0-9a-f]+:$', p[0]):
            yield int(p[0].strip()[:-1], 16), p[1].strip(), p[2].strip(), p[3].strip() if len(p) > 3 else ''

def ext_class(op):
    if op.startswith(('sexw', 'sexb')) or (op.startswith('ld') and '.x' in op): return 'signed'
    if op.startswith(('extw', 'extb', 'ldb', 'ldh', 'ldw')): return 'unsigned'
    return None

def main():
    b = BS[0]; a = b['load_address_candidate']
    rows = list(rows_of(disasm(a, a + b['size'])))
    res = {'block': 0, 'base': hex(a), 'size': hex(b['size'])}
    for fam in ('muldw', 'muludw', 'mulrdw'):
        st = collections.Counter(); reads = collections.Counter(); ext = collections.Counter(); sites = []
        for i, (pc, by, op, args) in enumerate(rows):
            if op != fam: continue
            st['decoded'] += 1
            nxt = ' '.join(x[3] for x in rows[i + 1:i + 4])
            used = tuple(sorted(set(re.findall(r'\br5[67]\b', nxt))))
            if not (args.startswith('0,') and used): continue  # shortcut: heuristic for real code, linear disasm may misdecode data
            st['real'] += 1; reads['+'.join(used)] += 1; sites.append(hex(pc))
            hi, lo = (int(w, 16) for w in by.split()[:2]); word = hi << 16 | lo
            bb = ((word >> 24) & 7) | (((word >> 12) & 7) << 3); cc = (word >> 6) & 63
            if (word & 0xf8ff803f) in (0x280c003e, 0x280d003e) and bb < 32 and cc < 32: st['v7_decoded'] += 1
            else: st['v7_not_decoded'] += 1
            if any('macmode' in x[3] for x in rows[max(0, i - 4):i]): st['macmode_write_within4'] += 1
            for r in re.findall(r'\br\d+\b', args.split(',', 1)[1]):
                for _, _, o2, a2 in reversed(rows[max(0, i - 10):i]):
                    if a2.split(',')[0] == r:
                        k = ext_class(o2)
                        if k: ext[k] += 1
                        break
        res[fam] = dict(status=dict(st), r56_r57_reads=dict(reads), operand_extension=dict(ext), real_sites=sites)
    mm = collections.Counter(f'{op} {args}' for _, _, op, args in rows if 'macmode' in args)
    res['macmode_accesses'] = dict(mm.most_common())
    res['macmode_or8_sites'] = [hex(pc) for i, (pc, _, op, args) in enumerate(rows)
                                if op == 'or' and args.endswith(',0x8') and i and 'macmode' in rows[i - 1][3]]
    assert res['muludw']['status']['real'] > 1000 and res['muldw']['status']['real'] > 200, 'census changed'
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'census.json').write_text(json.dumps(res, indent=1))
    for f in ('muldw', 'muludw', 'mulrdw'): print(f, res[f]['status'], res[f]['r56_r57_reads'], res[f]['operand_extension'])
    print('macmode |=8 sites:', res['macmode_or8_sites'])

if __name__ == '__main__':
    main()
