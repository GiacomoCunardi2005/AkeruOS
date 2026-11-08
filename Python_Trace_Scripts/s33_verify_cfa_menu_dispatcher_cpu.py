#!/usr/bin/env python3
"""Exercise original V1.1 CFA dispatcher with synthetic lower-level file services."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
import struct
import sys
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha
from s33_verify_gnu_dsp_lab import LAB, BUILD, compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS, PS, EXPECTED, ORIGINAL, raw, locate, disasm, u32


def main():
    assert sys.argv[1:] in ([], ['--geometry'], ['--backend'], ['--device'])
    geometry = bool(sys.argv[1:]); device = sys.argv[1:] == ['--device']; backend = sys.argv[1:] == ['--backend']
    prefix = 'cfa_device_cpu_' if device else ('cfa_backend_cpu_' if backend else ('cfa_geometry_cpu_' if geometry else 'cfa_menu_dispatcher_cpu_'))
    out=ROOT/'Risultati/HiddenMenu_RAW'/datetime.now(timezone.utc).strftime(prefix+'%Y%m%dT%H%M%S%fZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='cfa-menu-dispatcher'))
    print('Prove:',out,flush=True)
    try:
        r.prepare(); assert sha(ORIGINAL)==EXPECTED
        dump=ROOT/'DUMPS/MainCode.dmp'; d=dump.read_bytes();r.input_hashes[str(dump)]=sha(dump)
        sim=LAB/'install/bin/arc-elf32-run'; assert sha(sim)==json.loads(BUILD.read_text())['experimental_sha256']
        r.experimental_engine=LAB;r.input_hashes[str(sim)]=sha(sim);r.input_hashes[str(BUILD)]=sha(BUILD)
        spans=[(0x28d66c,0x28d6d8),(0x28d6e6,0x28d742),(0x28d7da,0x28d818),(0x7cf024,0x7cf054),(0x7cf51c,0x7cf570),(0x1e6a54,0x1e6ad0)]
        if backend or device: spans += [(0x12bcc4,0x12bce4),(0x18b0bc,0x18b0fc)]
        if device: spans += [(0x12de3c,0x12df00)]
        assert (u32(0x987058),u32(0x98705c))==(0x5004,0x7cf51c)
        for a,b in spans:
            block,off=locate(a,b-a);assert raw(a,b-a)==d[block['offset']+off:block['offset']+off+b-a]
        (out/'gnu_windows.txt').write_text('\n'.join(disasm(a,b) for a,b in spans))
        def binary(name,asm):
            elf=compile_probe(r,name,asm);path=out/(name+'.bin')
            p=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,path]);assert p.returncode==0,p.stdout
            return path.read_bytes()
        zero=' mov r0,0\n j_s [blink]\n'
        name='B:\\DCIM\\DSCN1000.JPG\0'
        name_asm=''
        for i,c in enumerate(name.encode()):name_asm+=f' mov r0,{c}\n stb r0,[r1,{i}]\n'
        name_asm+=' mov r0,0\n j_s [blink]\n'
        fixtures=[('stop',0x1e6acc,' j [r26]\n'),('lookup',0x635bd8,zero),('update',0x636040,zero),('refresh',0x145150,zero),('guard1',0x13bedc,zero),('guard2',0x13beec,zero),('query',0x12b0dc,zero),
          ('ready',0x12b934,' mov r0,1\n stb r0,[r1]\n mov r0,0\n j_s [blink]\n'),
          ('name',0x1378b4,name_asm),
          ('open',0x12bc20,''' mov r10,0x2010000
 ld r11,[r10,12]
 add r11,r11,1
 st r11,[r10,12]
 mov r11,''' + ('0x2011000' if device else '0x1234') + '''
 st r11,[r3]
 mov r11,0
 cp_name:
 add r12,r0,r11
 ldb r12,[r12]
 add r9,r10,r11
 stb r12,[r9,64]
 add r11,r11,1
 cmp r11,24
 blo cp_name
 ld r0,[r10]
 j_s [blink]
'''),
          ('write',0x1fa090 if device else (0x12de3c if backend else 0x12bcc4),''' mov r10,0x2010000
 ld r11,[r10,16]
 add r11,r11,1
 st r11,[r10,16]
 st r0,[r10,44]
 st r1,[r10,48]
 st r2,[r10,24]
 st r3,[r10,60]
''' + (''' mov r11,0x376018
 ld r11,[r11,92]
 st r11,[r10,88]
 ld r0,[r10,28]
 j_s [blink]
''' if device else '''
 ld r11,[r10,28]
 st r11,[r4]
 ld r0,[r10,4]
 j_s [blink]
''')),
          ('close',0x12bce4,''' mov r10,0x2010000
 ld r11,[r10,20]
 add r11,r11,1
 st r11,[r10,20]
 st r0,[r10,52]
 ld r0,[r10,8]
 j_s [blink]
''')]
        if device:
            fixtures += [('volume_index',0x1f1a8c,' mov r0,0\n st r0,[r1]\n j_s [blink]\n'),
                         ('volume_guard',0x1f1b18,zero),('lock',0x1593ac,zero),('unlock',0x1594a4,zero)]
        images={i:bytearray(PS[i]) for i in range(6)}; patches=[]; services=[]
        for i,(name,addr,asm) in enumerate(fixtures):
            target=0x2030000+i*0x400; code=binary(name,asm); services.append((target,code))
            entry=binary('entry_'+name,f' mov_s r12,{target:#x}\n j_s [r12]\n')[:8]
            block,off=locate(addr,8);image=images[block['index']];assert image[off:off+8]==raw(addr,8)
            patches.append(dict(name=name,address=hex(addr),original=bytes(image[off:off+8]).hex(),fixture=entry.hex()));image[off:off+8]=entry
        specs=[('off',0,0,0,0,2048,2,17,19),('complete',1,0,0,0,2048,2,17,19),('short',1,0,0,0,0,2,17,19),('write_error',1,0,77,0,0,2,17,19),('open_error',1,78,0,0,2048,2,17,19),('close_error',1,0,0,79,2048,2,17,19)]
        if geometry:
            specs=[(f'{label}_{kind}',1,0,0,0,count,kind,4208,3152)
                   for kind,full in ((2,26527232),(1,19895424))
                   for label,count in (('full',full),('short_file',13284424),('short_payload',13263616))]
        rows=[]
        for name,enable,oe,we,ce,count,kind,width,height in specs:
            maps=[]
            def mmap(label,addr,data):
                path=out/(name+'_'+label+'.bin');path.write_bytes(data+bytes(8+(-len(data))%8))
                maps.extend(['--memory-mapfile','/result/'+path.name,'--memory-region',f'{addr:#x},{path.stat().st_size}']);return path
            for i,image in images.items():mmap('block'+str(i),BS[i]['load_address_candidate'],image)
            mmap('dispatcher_state',0x520000,bytes(0x1000))
            if device:
                handle=bytearray(256);struct.pack_into('<I',handle,0,0x2011200);struct.pack_into('<I',handle,12,0)
                mmap('handle',0x2011000,handle);mmap('handle_data',0x2011200,bytes(32))
            context=bytearray(1024);struct.pack_into('<I',context,8,kind);struct.pack_into('<I',context,492,0x2021000);mmap('context',0x2020000,context)
            payload=bytearray(128);struct.pack_into('<I',payload,4,0x12345678);struct.pack_into('<I',payload,16,0x2040000);struct.pack_into('<HH',payload,28,width,height);mmap('payload',0x2021000,payload)
            for i,(addr,code) in enumerate(services):mmap('service'+str(i),addr,code)
            state=bytearray(128);struct.pack_into('<3I',state,0,oe,we,ce);struct.pack_into('<I',state,28,count);path=mmap('state',0x2010000,state)
            asm=f""" mov r20,0x2010000
 mov r0,0
 mov r12,0x13af20
 jl [r12]
"""
            if device:
                asm+=' mov r0,0x376018\n mov r1,0xa5\n st r1,[r0,92]\n'
            if enable:
                asm+=""" mov r0,0x987000
 mov r1,0x5004
 mov r2,0
 mov r12,0x7cf024
 jl [r12]
"""
            asm+=""" mov r1,0x366c20
 ldb r0,[r1]
 st r0,[r20,56]
 st sp,[r20,32]
 mov r0,0x2020000
 mov r26,after_gate
 mov r12,0x1e6a54
 j [r12]
 after_gate:
 st r0,[r20,40]
""" + (''' mov r0,0x376018
 ld r0,[r0,92]
 st r0,[r20,92]
''' if device else '') + """
 ld sp,[r20,32]
 mov r0,0
 mov r8,1
 trap_s 1
"""
            elf=compile_probe(r,name,asm);result,log=r.run(name,'/result/'+elf.name,maps,trace=True)
            assert result['exit_code']==0 and result['fault'] is None,log
            w=struct.unpack_from('<16I',path.read_bytes());filename=path.read_bytes()[64:88].split(b'\0')[0].decode()
            assert w[14]==enable,(name,w)
            expected_calls=(1,1,1) if enable else (0,0,0)
            assert (w[3],w[4],w[5])==expected_calls,(name,w)
            if enable:
                assert filename=='B:\\DCIM\\CFAi1000.raw',(name,filename)
                expected=((width+15)//16*16)*((height+15)//16*16)
                expected=expected*2 if kind==2 else expected*3//2
                assert (w[11],w[12],w[6])==((0x2011000 if device else 0x1234),0x2040000,expected),(name,w,expected)
                if backend: assert w[15]==1,(name,w)
                if device: assert struct.unpack_from('<2I',path.read_bytes(),88)==(1,0),(name,path.read_bytes()[88:96].hex())
                assert w[10]==ce,(name,w)
            trace=(out/(name+'.trace')).read_text()
            has_short=any(line.startswith('0x28d80a ') and '0x700103' in line for line in trace.splitlines())
            assert has_short==name.startswith('short'),(name,has_short)
            for pc in (['0x7cf024','0x7cf51c','0x1e6a54','0x28d66c'] if enable else ['0x1e6a54']):
                assert any(line.startswith(pc+' ') for line in trace.splitlines()),(name,pc)
            if backend:
                for pc in ('0x12bcc4','0x18b0bc','0x12de3c'):
                    assert sum(line.startswith(pc+' ') for line in trace.splitlines())==1,(name,pc)
            if device:
                for pc in ('0x12bcc4','0x18b0bc','0x12de3c','0x1fa090'):
                    assert sum(line.startswith(pc+' ') for line in trace.splitlines())==1,(name,pc)
            rows.append(dict(name=name,flag=w[14],format_kind=kind,width=width,height=height,open_calls=w[3],write_calls=w[4],close_calls=w[5],requested=w[6],reported=count,short_error_branch=has_short,close_status_at_stop=w[10],filename=filename))
        (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n');(out/'fixture_patches.json').write_text(json.dumps(patches,indent=2)+'\n');(out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_CFA_MENU_DISPATCHER_CPU_FIXTURES',scenarios=rows,assumptions=['Event wrapper, callback, gate prefix and dispatcher original; UI and file services synthetic.', 'Gate calls modes sequentially, stop before 1E6ACC; event injected and gate invoked by harness.', 'GNU DSP model experimental.'] + (['Write wrappers 12BCC4 and 18B0BC original; lower 12DE3C is fixture.'] if backend else []) + (['12DE3C original; volume lookup, guard, locks and 1FA090 are fixtures; handle and file error are synthetic.'] if device else []),limits=['No sensor, actual data or filesystem. A return status does not establish persistence.', 'Open failure fixture writes a handle anyway; no conclusions about real failed-open handle state.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print('PASS',out,flush=True)

if __name__=='__main__':main()
