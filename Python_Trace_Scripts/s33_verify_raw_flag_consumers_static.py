#!/usr/bin/env python3
"""Anchor the existing linear-disassembly RAW getter candidates to V1.1 bytes."""
from datetime import datetime, timezone
from pathlib import Path
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import EXPECTED, ORIGINAL, raw, locate, sha, disasm, u32, cstring
from catalog_hiddenmenu import parse_lines


def main():
    dump=(ROOT/'DUMPS/MainCode.dmp').read_bytes()
    assert sha(ORIGINAL.read_bytes())==EXPECTED
    candidate_file=ROOT/'Risultati/HiddenMenu_RAW/20261027_static/branch_candidates.json'
    candidates=[int(x['pc'],16) for x in json.loads(candidate_file.read_text()) if x['target']=='0x28d48c']
    expected=[0x1b91ec,0x1b9292,0x1b933a,0x1b990a,0x1baa28,0x1bc09c,0x1bc51e,0x1bc7cc,0x1bcc70,0x7cf134,0x7cf1fa,0x7cf4f8,0x7cf7f0,0x7cf810]
    assert candidates==expected
    rows,listings,spans={},[],[]
    for start in candidates:
        for end in range(start+160,start+200,2):
            try:
                listing=disasm(start,end)
                break
            except AssertionError:
                continue
        else:
            raise AssertionError(f'Could not disassemble {start:#x}')
        data=raw(start,end-start)
        block,offset=locate(start,end-start)
        assert data==dump[block['offset']+offset:block['offset']+offset+len(data)]
        parsed={r['address']:r for r in parse_lines(listing)}
        assert parsed[start]['op']=='bl' and ';0x28d48c' in parsed[start]['args']
        rows.update(parsed);listings.append(listing)
        spans.append(dict(start=hex(start),end_exclusive=hex(end),sha256=sha(data)))
    checks=[(0x1b91f0,'cmp_s','r0,0x1'),(0x1b91f2,'bne_s',';0x1b923a'),
      (0x1b9296,'cmp_s','r0,0'),(0x1b9298,'beq_s',';0x1b933a'),
      (0x1b933e,'cmp_s','r0,0'),(0x1b9340,'beq_s',';0x1b93a0'),
      (0x1b9912,'cmp_s','r0,0'),(0x1b9914,'beq_s',';0x1b994e'),(0x1b994a,'bl',';0x28d4d4'),
      (0x1baa4c,'cmp_s','r0,0x1'),(0x1baa4e,'bne_s',';0x1baa76'),(0x1baa5e,'bl',';0x17d62c'),(0x1baa7c,'bl',';0x17d458'),
      (0x1bc0a0,'mov_s','r1,r0'),(0x1bc0dc,'cmp_s','r1,0x1'),(0x1bc0de,'bne_s',';0x1bc106'),(0x1bc0ee,'bl',';0x17d62c'),(0x1bc10c,'bl',';0x17d458'),
      (0x1bc522,'cmp_s','r0,0x1'),(0x1bc524,'bne_s',';0x1bc56a'),(0x1bc55a,'bl',';0x28d4d4'),
      (0x1bc7d0,'mov_s','r1,r0'),(0x1bc802,'cmp_s','r1,0x1'),(0x1bc804,'bne_s',';0x1bc832'),(0x1bc81a,'bl',';0x17d62c'),(0x1bc83e,'bl',';0x17d458'),
      (0x1bcc74,'cmp_s','r0,0x1'),(0x1bcc76,'bne_s',';0x1bccbe'),(0x1bccae,'bl',';0x28d4d4'),
      (0x7cf138,'cmp_s','r0,0x1'),(0x7cf13a,'bne_s',';0x7cf140'),
      (0x7cf1fe,'cmp_s','r0,0x1'),(0x7cf200,'bne_s',';0x7cf206'),
      (0x7cf4fc,'cmp_s','r0,0'),(0x7cf500,'sub_s.ne','r0,r0,r0'),(0x7cf502,'bl',';0x28d498'),
      (0x7cf7f4,'cmp_s','r0,0'),(0x7cf7f8,'sub_s.ne','r0,r0,r0'),(0x7cf7fa,'bl',';0x28d498'),
      (0x7cf814,'cmp_s','r0,0'),(0x7cf816,'beq_s',';0x7cf81c'),(0x7cf818,'mov_s','r0,0x3')]
    for pc,op,arg in checks:
        assert rows[pc]['op']==op and arg in rows[pc]['args'],rows[pc]
    labels={0x7cf2e0:'SaveCFAonTake:On',0x7cf2e4:'SaveCFAonTake:Off',
            0x7cf328:'Take12BitCCDRaw:On',0x7cf32c:'Take12BitCCDRaw:Off'}
    for addr,label in labels.items():
        block,offset=locate(addr,4)
        assert raw(addr,4)==dump[block['offset']+offset:block['offset']+offset+4]
        p=u32(addr); encoded=label.encode()+b'\0'
        block,offset=locate(p,len(encoded))
        assert raw(p,len(encoded))==encoded==dump[block['offset']+offset:block['offset']+offset+len(encoded)]
        assert cstring(p)==label
    out=ROOT/'Risultati/HiddenMenu_RAW'/datetime.now(timezone.utc).strftime('flag_consumers_static_%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True)
    (out/'gnu_windows.txt').write_text('\n'.join(listings))
    (out/'evidence.json').write_text(json.dumps(dict(status='PASS_STATIC_EXISTING_CANDIDATES',
       source_sha256=EXPECTED,dump_sha256=sha(dump),candidate_list_sha256=sha(candidate_file.read_bytes()),
       source_spans=spans,verified_calls=[hex(x) for x in candidates],checked_instructions=len(checks),
       labels={hex(k):v for k,v in labels.items()},
       limits=['Uses previously generated direct branch candidate list from linear disassembly blocks 0-10; no proof of complete reachable code.',
               'Indirect calls, other payloads and aliases/direct RAM access may exist; this is not whole-firmware coverage.',
               'Static branch conditions do not prove runtime reachability, service effects, buffer, or hardware behavior.',
               'The behavior of helper routines 17D62C and 17D458 is not characterized here.']),indent=2)+'\n')
    print(out)

if __name__=='__main__': main()
