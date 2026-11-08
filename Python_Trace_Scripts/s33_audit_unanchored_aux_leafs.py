#!/usr/bin/env python3
"""Bounded search for callers of 13 AUX leafs; reject overlapping encodings.

Leaf structure is not global reachability or a Nikon register admission.
"""
import json,re,struct,shutil
from pathlib import Path
from datetime import datetime,timezone
from collections import deque
from s33_integrate_ffc7000_table_tail import ROOT,load,save,sha
from s33_trace_state_dispatch import verified_payloads
from s33_verify_sensor_mmio_dialog import aligned_window
from s33_verify_custom_aux_cfg import call_at,sx
from s33_verify_fe9_tail_callers import branch_at

PARENT=ROOT/'Risultati/Processor_Registers/20261025T202612Z'
SPECS=[(0x319aac,0x319ab8,0x1028b,'read_low8'),(0x319ab8,0x319acc,0x1028b,'read_bits8_15'),
 (0x319acc,0x319ae0,0x1028b,'read_bits16_23'),(0x319ae0,0x319af4,0x1028b,'read_bits24_29'),
 (0x342bd0,0x342be4,0x10004,'set_bit7'),(0x342be4,0x342bf8,0x10004,'clear_bit7'),
 (0x342bf8,0x342c06,0x10004,'read_bit7'),(0x342c88,0x342ca2,0x10031,'replace_low4'),
 (0x342cc0,0x342cda,0x10033,'replace_low4'),(0x342cf8,0x342d0c,0x10035,'set_bit0'),
 (0x342d0c,0x342d20,0x10035,'clear_bit0'),(0x342e4c,0x342e68,0x10038,'set_bit0_iff_nonzero'),
 (0x342e68,0x342e74,0x10038,'read_bit0')]


def main():
    ledger=load(PARENT/'sha256.json');assert all(sha(PARENT/k)==v for k,v in ledger.items())
    blocks,payloads,directory=verified_payloads(ROOT);targets={s[0] for s in SPECS}
    inputs={str(q):sha(q) for q in [Path(__file__),PARENT/'sha256.json',ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin',
        ROOT/'work/build-arc/binutils/objdump',ROOT/'work/build-arc/binutils/objcopy']}
    for n in ['s33_trace_state_dispatch','s33_verify_sensor_mmio_dialog','s33_verify_custom_aux_cfg','s33_verify_fe9_tail_callers','s33_integrate_ffc7000_table_tail']:
        q=Path(__file__).with_name(n+'.py');inputs[str(q)]=sha(q)
    cache={}
    def decode(block,pc):
        key=block,pc
        if key not in cache:
            z=blocks[block];base=z['load_address_candidate'];blob=payloads[block]
            text=aligned_window(blob,base,pc,pc+12);line=next(x for x in text.splitlines() if re.match(r'\s*'+f'{pc:x}:',x))
            m=re.match(r'\s*[0-9a-f]+:\s+((?:[0-9a-f]{4}\s+)+)\t(\S+)\s*(.*)',line)
            raw=b''.join(bytes.fromhex(w)[::-1] for w in m[1].split());assert raw==blob[pc-base:pc-base+len(raw)]
            cache[key]=dict(payload=block,pc=hex(pc),opcode=m[2],operands=m[3].strip(),size=len(raw),bytes_hex=raw.hex())
        return cache[key]
    leafs=[]
    for entry,end,index,role in SPECS:
        todo=deque([entry]);visited={};edges=[];returns=[];aux=[]
        while todo:
            pc=todo.popleft()
            if pc in visited:continue
            assert entry<=pc<end,(hex(entry),hex(pc))
            ins=decode(0,pc);visited[pc]=ins;nxt=pc+ins['size'];op=ins['opcode']
            assert op not in ['.word','.short','.invalid','bl','bl.d','bl_s','jl','jl_s','jl_s.d']
            if op in ['lr','sr']:
                assert f'[{hex(index)}]' in ins['operands'];aux.append(dict(pc=hex(pc),operation='read' if op=='lr' else 'write',index=hex(index)))
            if op in ['j_s','j_s.d']:
                assert ins['operands']=='[blink]'
                if op.endswith('.d'):
                    delay=decode(0,nxt);assert nxt+delay['size']<=end and delay['opcode'] not in ['lr','sr','j_s','j_s.d']
                    visited[nxt]=delay;edges.append(dict(source=hex(pc),target=hex(nxt),kind='return_delay'))
                returns.append(hex(pc));continue
            if op in ['b_s','bne_s']:
                target=int(re.search(r';(?:0x)?([0-9a-f]+)',ins['operands'])[1],16)
                edges.append(dict(source=hex(pc),target=hex(target),kind='branch'));todo.append(target)
                if op=='b_s':continue
            edges.append(dict(source=hex(pc),target=hex(nxt),kind='fallthrough'));todo.append(nxt)
        assert returns and aux
        leafs.append(dict(entry=hex(entry),end_exclusive=hex(end),index=hex(index),software_role_candidate=role,
            instructions=[v for k,v in sorted(visited.items())],edges=edges,returns=returns,aux_sites=aux,
            classification='well_formed_bounded_leaf_no_qualified_incoming_reference',register_admitted=False))
    matches=[];pointers=[];coverage=[]
    for b in blocks:
        blob=payloads[b['index']];base=b['load_address_candidate'];inputs[str(directory/b['file'])]=sha(directory/b['file'])
        for off in range(0,len(blob)-1,2):
            branch=branch_at(blob,off,base)
            call=call_at(blob,off,base) if off+4<=len(blob) else None
            if off+4>len(blob):
                h=struct.unpack_from('<H',blob,off)[0]
                if h&0xf800==0xf800:call=dict(pc=base+off,target=((base+off)&~3)+sx((h&0x7ff)<<2,13),size=2,encoding='bl_s_final_halfword')
            for kind,c in [('B',branch),('BL',call)]:
                if c and c['target'] in targets:
                    own=decode(b['index'],c['pc']);assert own['size']==c['size'] and int(re.search(r';(?:0x)?([0-9a-f]+)',own['operands'])[1],16)==c['target']
                    matches.append(dict(payload=b['index'],kind=kind,**c,standalone_decode=own))
        for target in targets:
            for order,needle in [('word_LE',struct.pack('<I',target)),('LIMM_halfwords_LE',struct.pack('<HH',target>>16,target&65535))]:
                start=0
                while (off:=blob.find(needle,start))>=0:pointers.append(dict(payload=b['index'],address=hex(base+off),target=hex(target),encoding=order));start=off+1
        coverage.append(dict(payload=b['index'],base=hex(base),byte_size=len(blob),halfword_positions=len(blob)//2,sha256=sha(directory/b['file'])))
    assert len(matches)==5 and not pointers
    owners={(0,0x2f1dd0):0x2f1dce,(0,0x33550e):0x335508,(0,0x34258c):0x34258a,(0,0x343812):0x34380e,(3,0x703272):0x703270}
    assert {(x['payload'],x['pc']) for x in matches}==set(owners)
    for m in matches:
        owner=decode(m['payload'],owners[m['payload'],m['pc']]);start=int(owner['pc'],0)
        assert start<m['pc']<start+owner['size']
        assert owner['opcode'] in ['asl','mov','lr','mov_s','stb.di.as']
        m.update(covering_instruction=owner,overlap_offset=m['pc']-start,
            candidate_crosses_covering_instruction_end=m['pc']+m['size']>start+owner['size'],
            classification='overlaps_longer_instruction_in_retained_decode_phase_not_qualified_caller',qualified=False)
    old=load(PARENT/'register_map.json');known={r['number'] for r in old['records'] if r['space']=='aux'}
    assert {s[2] for s in SPECS}=={0x1028b,0x10004,0x10031,0x10033,0x10035,0x10038}
    assert not known&{s[2] for s in SPECS}
    assert all(sha(Path(k))==v for k,v in inputs.items()) and all(sha(PARENT/k)==v for k,v in ledger.items())
    out=ROOT/'Risultati/Processor_Register_AUX_Candidates'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ');out.mkdir(parents=True,exist_ok=False)
    shutil.copy2(Path(__file__),out/Path(__file__).name)
    save(out/'verified_evidence.json',dict(status='PASS_BOUNDED_UNANCHORED_AUX_LEAF_AUDIT',date='2026-10-25',parent_atlas=str(PARENT),
        leafs=leafs,candidate_edges=matches,pointer_matches=pointers,payload_coverage=coverage,input_sha256=inputs,
        decoded_instructions=list(cache.values()),new_register_admissions=0,atlas_modified=False,hardware_access=False,gnu_modified=False,
        global_unreachability_proven=False,
        limits=['Search covers B_s/Bcc_s/Bsimm21/25 andBLfamilies atcompletehalfwords plusLE/LIMMpattern literals atallbyteoffsets in16payloads.',
            'ExcludesTBIB,BRcc,BBIT,LP,registerjumps,computed/encrypted pointers,externalcode,interiorentryandnonstandardinstructionphases.',
            'Local leafstructure andoverlaprejection do not prove globalabsenceofcallers orphysicalregisterimplementation.',
            'All6indices remaincandidates,not data-only declarations orscalarregisteradmissions.']))
    save(out/'sha256.json',{p.name:sha(p) for p in sorted(out.iterdir()) if p.is_file()})
    print('PASS13leafs/6candidateindices;5overlaps/0qualifiededges;0literalpointers;atlas unchanged');print(out)


if __name__=='__main__':main()
