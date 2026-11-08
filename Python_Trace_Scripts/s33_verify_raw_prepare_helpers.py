#!/usr/bin/env python3
"""Compare V1.1 RAW-related configuration helpers, with bounded CPU probe."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, EXPECTED, ORIGINAL, raw, locate, disasm, u32
from catalog_hiddenmenu import parse_lines


def main():
    out=ROOT/'Risultati/HiddenMenu_RAW'/datetime.now(timezone.utc).strftime('prepare_helpers_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='raw-prepare-helpers'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        assert sha(ORIGINAL)==EXPECTED
        dump=ROOT/'DUMPS/MainCode.dmp';data=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
        spans=[(0x17d458,0x17d624),(0x17d62c,0x17d680),
               (0x1baa28,0x1baa80),(0x1bc09c,0x1bc110),(0x1bc7cc,0x1bc842)]
        rows={};listings=[];windows=[]
        for start,end in spans:
            payload=raw(start,end-start);block,off=locate(start,end-start)
            assert payload==data[block['offset']+off:block['offset']+off+len(payload)]
            listing=disasm(start,end);rows.update({x['address']:x for x in parse_lines(listing)})
            listings.append(listing);windows.append(dict(start=hex(start),end_exclusive=hex(end),sha256=__import__('hashlib').sha256(payload).hexdigest()))
        checks=[(0x17d46c,'st','r1,[fp,40]'),(0x17d470,'st','r2,[fp,44]'),
                (0x17d492,'bl',';0x1dacc8'),(0x17d49c,'ld_s','r0,[r15,0]'),
                (0x17d49e,'bset_s','r0,r0,0x3'),(0x17d4a0,'bset_s','r0,r0,0xc'),
                (0x17d4a2,'bset_s','r0,r0,0xd'),(0x17d4a4,'st_s','r0,[r14,0]'),
                (0x17d4b8,'beq_s',';0x17d564'),(0x17d4c0,'beq_s',';0x17d564'),
                (0x17d5c2,'ldh','r1,[fp,40]'),(0x17d5da,'sth.as','r0,[r14,216]'),
                (0x17d5de,'ldh','r0,[fp,42]'),(0x17d5f4,'sth.as','r0,[r14,217]'),
                (0x17d5f8,'ldh','r0,[fp,44]'),(0x17d60e,'sth.as','r0,[r14,218]'),
                (0x17d63e,'st','r1,[fp,12]'),(0x17d642,'st','r2,[fp,16]'),
                (0x17d64c,'bl',';0xdf47c'),(0x17d650,'mov_s','r0,0x3'),
                (0x17d652,'asl_s','r0,r0,0xc'),(0x17d654,'st_s','r0,[r13,0]'),
                (0x17d656,'ldh','r0,[fp,-122]'),(0x17d65c,'add','r12,r12,590'),
                (0x17d660,'stw_s','r0,[r12,0]'),(0x17d662,'ld','r0,[fp,-156]'),
                (0x17d668,'add','r12,r12,588'),(0x17d66c,'stb_s','r0,[r12,0]'),
                (0x1baa4c,'cmp_s','r0,0x1'),(0x1baa54,'cmp_s','r0,0x3'),
                (0x1baa5e,'bl',';0x17d62c'),(0x1baa7c,'bl',';0x17d458'),
                (0x1bc0dc,'cmp_s','r1,0x1'),(0x1bc0e4,'cmp_s','r0,0x3'),
                (0x1bc0ee,'bl',';0x17d62c'),(0x1bc10c,'bl',';0x17d458'),
                (0x1bc802,'cmp_s','r1,0x1'),(0x1bc80a,'cmp_s','r0,0x3'),
                (0x1bc81a,'bl',';0x17d62c'),(0x1bc83e,'bl',';0x17d458')]
        for pc,op,arg in checks:
            assert rows[pc]['op']==op and arg in rows[pc]['args'],rows[pc]
        assert u32(0x17d628)==0x3008
        block,off=locate(0x17d628,4);assert raw(0x17d628,4)==data[block['offset']+off:block['offset']+off+4]
        (out/'gnu_windows.txt').write_text('\n'.join(listings))
        images={i:bytearray(PS[i]) for i in (0,1,2,3,4,5)}
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin')
            p=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path])
            assert p.returncode==0,p.stdout
            b=path.read_bytes();path.write_bytes(b+bytes(8+(-len(b))%8));return path
        def mapping(path,addr):
            return ['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']
        fixture=binary('fixture_df47c',''' mov r1,0x12345678
 st r1,[r0,4]
 mov r1,0xabcd
 sth r1,[r0,38]
 mov r0,0
 j_s [blink]
''')
        target=0x2030000
        maps=mapping(fixture,target)
        entry=binary('fixture_entry',f' mov_s r12,{target:#x}\n j_s [r12]\n').read_bytes()[:8]
        block,off=locate(0xdf47c,8);before=bytes(images[block['index']][off:off+8]);assert before==raw(0xdf47c,8)
        images[block['index']][off:off+8]=entry
        for i,image in images.items():
            path=out/f'block{i}_LAB_FIXTURE.bin';path.write_bytes(image);maps+=mapping(path,BS[i]['load_address_candidate'])
        # Full output and 16-byte guards are checked; fields unrelated to these fixtures stay sentinel.
        records=out/'records.bin';records.write_bytes(bytes([0xa5])*2048);maps+=mapping(records,0x2020000)
        results=out/'results.bin';results.write_bytes(bytes(64));maps+=mapping(results,0x2001000)
        asm=' mov r20,0x2001000\n'
        for i,(arg1,arg2) in enumerate([(0,0),(0xdeadbeef,0x12345678)]):
            asm+=f''' st sp,[r20,{i*12}]
 mov r0,{0x2020010+i*1024:#x}
 mov r1,{arg1:#x}
 mov r2,{arg2:#x}
 mov r12,0x17d62c
 jl [r12]
 st r0,[r20,{i*12+4}]
 st sp,[r20,{i*12+8}]
'''
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        elf=compile_probe(r,'cases',asm)
        case,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        words=struct.unpack('<16I',results.read_bytes());b=records.read_bytes();rows_out=[]
        for i in range(2):
            expected=bytearray([0xa5])*1024
            struct.pack_into('<I',expected,16,0x3000);expected[16+588]=0x78;struct.pack_into('<H',expected,16+590,0xabcd)
            assert b[i*1024:(i+1)*1024]==expected
            assert words[i*3]==words[i*3+2] and words[i*3+1]==0
            rows_out.append(dict(case=i,initial_args=list(map(hex,[(0,0),(0xdeadbeef,0x12345678)][i])),word='0x3000',byte588='0x78',halfword590='0xabcd',stack_preserved=True))
        trace=(out/'cases.trace').read_text()
        for address in ('0x17d62c','0x17d64c','0x17d650','0x17d66c','0x17d67a'):
            assert any(x.startswith(address+' ') for x in trace.splitlines()),address
        (out/'fixture_patch.json').write_text(json.dumps(dict(address='0xdf47c',original=before.hex(),fixture=entry.hex(),behavior='write 0x12345678 to argument+4 and 0xabcd to argument+38'),indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_BOUNDED_RAW_HELPERS_STATIC_AND_SPECIAL_CPU',source_spans=windows,
            checked_instructions=len(checks),scenarios=rows_out,
            assumptions=['Original 17D62C CPU; DF47C replaced with synthetic output producer, no actual image memory.',
                         'Static only for 17D458 and three callers; actual nested helpers, input, runtime order and ownership unknown.'],
            limits=['No complete CPU execution of 17D458 or real DF47C; no physical camera, file I/O, image buffer or JPEG.',
                    'Different configuration words do not establish incompatibility or necessity for the 2N writer.',
                    'Argument/frame semantics and downstream interpretation are not established.'])
        r.finish()
    except Exception as e:
        r.results.update(status='FAIL',error=repr(e));raise
    finally:r.save()
    print('PASS: static comparison and synthetic special helper CPU;',out,flush=True)

if __name__=='__main__':main()
