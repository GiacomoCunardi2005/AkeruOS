#!/usr/bin/env python3
"""Verify the middle-128 path to the triplet setter with synthetic data."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, struct, sys

from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0, str(ROOT / 'S33-sections/analysis_codex'))
from static_common import BS, PS, locate, raw


def main():
    normalize = '--normalize' in sys.argv
    out = ROOT / 'Risultati/Mono_RAW' / datetime.now(timezone.utc).strftime(('cfa_awb_normalize_cpu_' if normalize else 'cfa_awb_caller_cpu_') + '%Y%m%dT%H%M%SZ')
    r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN, output=out, action='cfa-awb-caller'))
    print('Prove:', out, flush=True)
    try:
        r.prepare(); dump = ROOT / 'DUMPS/MainCode.dmp'; data = dump.read_bytes()
        for p in (dump, Path(__file__)): r.input_hashes[str(p)] = sha(p)
        for addr, size in ((0x10bf64, 0xb4), (0xe5408, 8)):
            b, o = locate(addr, size); assert raw(addr, size) == data[b['offset']+o:b['offset']+o+size]
        def binary(name, asm):
            elf = compile_probe(r, name, asm); p = out / (name + '.bin')
            result = r.command(name+'_extract', [TOOLCHAIN/'arc-elf32-objcopy', '-O', 'binary', '--only-section=.text', elf, p])
            assert result.returncode == 0, result.stdout
            b = p.read_bytes(); p.write_bytes(b + bytes(8 + (-len(b)) % 8)); return p
        def mapping(p, addr): return ['--memory-mapfile', '/result/'+p.name, '--memory-region', f'{addr:#x},{p.stat().st_size}']
        recorder = binary('setter_recorder', ''' mov r10,0x2000000
 ld r10,[r10]
 ldh r11,[r2]
 st r11,[r10]
 ldh r11,[r2,2]
 st r11,[r10,4]
 ldh r11,[r2,4]
 st r11,[r10,8]
 st r3,[r10,12]
 mov r0,0
 j_s [blink]
''')
        entry = binary('entry_recorder', ' mov_s r12,0x2030000\n j_s [r12]\n').read_bytes()[:8]
        images = {i: bytearray(PS[i]) for i in (0,1)}
        b,o=locate(0xe5408,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(0xe5408,8)
        images[b['index']][o:o+8]=entry
        extra_maps = []
        patches = [{'address':'0xe5408','original':before.hex(),'fixture':entry.hex()}]
        if normalize:
            seed = binary('coefficient_fixture', ' mov r10,0x2000000\n ld r10,[r10]\n ld r0,[r10,24]\n st r0,[r1]\n ld r0,[r10,28]\n st r0,[r1,8]\n mov r0,0\n j_s [blink]\n')
            seed_entry = binary('coefficient_entry',' mov_s r12,0x2030400\n j_s [r12]\n').read_bytes()[:8]
            b,o=locate(0xfbe68,8); before=bytes(images[b['index']][o:o+8]); assert before==raw(0xfbe68,8)
            images[b['index']][o:o+8]=seed_entry; extra_maps += mapping(seed,0x2030400)
            patches.append({'address':'0xfbe68','original':before.hex(),'fixture':seed_entry.hex()})
        cases=([(100,64,200),(100,256,200),(100,64,200),(100,64,200),(162,127,113),(255,256,100),(128,128,128)] if normalize else
               [(162,128,113),(0,128,65535),(128,128,128)])
        coefficients=([(1.,1.),(1.,1.),(2.,1.),(1.,.5),(1.,1.),(1.,1.),(1.,1.)] if normalize else [])
        asm=' mov r20,0x2000000\n'
        for i,vals in enumerate(cases):
            asm+=f''' mov r21,{0x2001000+i*32:#x}
 st r21,[r20]
 st sp,[r21,16]
 mov r0,0
 mov r1,{0x2002000+i*8:#x}
 mov r12,0x10bf64
 jl [r12]
 st sp,[r21,20]
'''
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        maps=mapping(recorder,0x2030000)+extra_maps
        for i,img in images.items():
            p=out/f'block{i}_LAB_FIXTURE.bin';p.write_bytes(img);maps+=mapping(p,BS[i]['load_address_candidate'])
        cur=out/'current.bin';cur.write_bytes(bytes(8));maps+=mapping(cur,0x2000000)
        state=out/'cases.bin'; state_data=bytearray(len(cases)*32)
        for i,coeff in enumerate(coefficients): struct.pack_into('<2f',state_data,i*32+24,*coeff)
        state.write_bytes(state_data);maps+=mapping(state,0x2001000)
        inputs=out/'inputs.bin';inputs.write_bytes(b''.join(struct.pack('<3H2x',*vals) for vals in cases));maps+=mapping(inputs,0x2002000)
        elf=compile_probe(r,'cases',asm);result,log=r.run('cases','/result/'+elf.name,maps,trace=True)
        assert result['exit_code']==0 and result['fault'] is None,log
        rows=[]
        for i,vals in enumerate(cases):
            w=struct.unpack_from('<6I',state.read_bytes(),i*32)
            if normalize:
                print('Osservazione', vals, coefficients[i], w[:3], flush=True)
                assert w[3]==0 and w[4]==w[5],(i,w)
            else: assert tuple(w[:3])==vals and w[3]==0 and w[4]==w[5],(i,w)
            rows.append({'input':vals,'fixture_coefficients':coefficients[i] if normalize else None,'setter_triplet':w[:3],'second_pointer':w[3],'stack_preserved':True})
        trace=(out/'cases.trace').read_text()
        for addr in ('0x10bf64','0x10c010','0x0e5408'):
            assert sum(line.startswith(addr+' ') for line in trace.splitlines())==len(cases),addr
        assert sum(line.startswith('0x10bf80 ') for line in trace.splitlines())==(1 if normalize else len(cases))
        if normalize: assert sum(line.startswith('0x0fbe68 ') for line in trace.splitlines())==len(cases)-1
        assert all(sha(Path(p))==h for p,h in r.input_hashes.items())
        (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        (out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='EXPLORATORY_NO_NUMERICAL_ORACLE' if normalize else 'PASS_AWB_MIDDLE_128_CALLER_SYNTHETIC',scenarios=rows,
            assumptions=['Direct call to original 10BF64 with synthetic inputs; original setter E5408 replaced by recorder.', 'Non-128 coefficient provider is a fixture supplying selected 32-bit float words.' if normalize else 'Middle value is 128.'],
            limits=['Physical channel meaning, actual values and file writing unverified.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('EXPLORATORY:' if normalize else 'PASS:',len(cases),'caller cases',out,flush=True)


if __name__=='__main__':main()
