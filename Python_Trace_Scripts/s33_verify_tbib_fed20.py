#!/usr/bin/env python3
"""Original TBIB FED20 accessors, fixed literal destinations, no firmware edits."""
import json,struct,shutil
from pathlib import Path
from types import SimpleNamespace
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,sha
from s33_verify_gnu_defined_memory import LAB,BUILD,known_sections
from s33_verify_ff7_transfer_windows import SeparatedRunner
from s33_verify_gnu_dsp_lab import compile_probe
from s33_integrate_ffc7000_table_tail import load

PARENT=ROOT/'Risultati/Processor_Registers/20261025T202612Z'
REUSED=ROOT/'outputs/gnu_arc700/20261025T202451Z_4bf1977d'
# entry, kind, address, bit; original pool and PC contracts audited separately.
SPECS=[(0x10031d8,'toggle',0xfed2000,0),(0x100320c,'set',0xfed2004,0),
 (0x1003228,'toggle',0xfed2008,2),(0x100325c,'toggle',0xfed200c,1),
 (0x1003290,'masked_split',0xfed2028,0),(0x10032d0,'split',0xfed2030,0),
 (0x10032f8,'store',0xfed203c,0),(0x100330c,'bit',0xfed2040,2),(0x1003324,'bit',0xfed2040,1),
 (0x100333c,'pair_to_RAM',0xfed2048,0),(0x100336c,'read',0xfed2050,0),
 (0x1003380,'bit',0xfed2068,3),(0x1003398,'read',0xfed2068,0),(0x10033ac,'bit',0xfed2068,4),
 (0x10033c4,'read',0xfed206c,0),(0x10033d8,'store',0xfed206c,0),
 (0x10033ec,'or_mask',0xfed2070,0),(0x1003410,'clear_mask',0xfed2070,0),
 (0x1003430,'inverse_toggle',0xfed2074,1),(0x1003464,'inverse_toggle',0xfed2074,0),
 (0x1003498,'toggle',0xfed2078,1),(0x10034cc,'toggle',0xfed2078,0),(0x1003500,'bit',0xfed2078,0),
 (0x1003518,'write48',0xfed2010,0),(0x100359c,'read48',0xfed2018,0),
 (0x1003610,'bit',0xfed2000,2),(0x1003628,'bit',0xfed2004,2),(0x1003640,'bit',0xfed2008,6),
 (0x1003658,'bit',0xfed200c,2),(0x1003670,'bit',0xfed2038,0),(0x1003688,'set',0xfed2038,1)]


def main():
    ledger=load(PARENT/'sha256.json');assert all(sha(PARENT/k)==v for k,v in ledger.items())
    fw=ROOT/'OriginalSoftware_NikonS33_V1.1/firmware.bin';original=fw.read_bytes()
    base,size,checksum,entry=struct.unpack_from('<4I',original,0x6c);tbib=original[0x7c:0x7c+size]
    assert len(tbib)==size and sum(x[0] for x in struct.iter_unpack('<I',tbib))&0xffffffff==checksum and base==entry==0x1000000
    r=SeparatedRunner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='original-tbib-fed20-accessors'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();r.known_ranges='';r.experimental_engine=LAB
        assert sha(LAB/'install/bin/arc-elf32-run')==load(BUILD)['engine_sha256']
        assert sha(REUSED/'observer')==load(REUSED/'verified_evidence.json')['files']['observer']
        shutil.copy2(REUSED/'observer',r.out/'observer');shutil.copy2(Path(__file__),r.out/Path(__file__).name)
        for p in [Path(__file__),PARENT/'sha256.json',fw,BUILD,LAB/'install/bin/arc-elf32-run',REUSED/'observer',REUSED/'verified_evidence.json']:
            r.input_hashes[str(p)]=sha(p)
        for n in ['s33_run_gnu_arc700','s33_verify_gnu_defined_memory','s33_verify_ff7_transfer_windows','s33_verify_gnu_dsp_lab','s33_integrate_ffc7000_table_tail']:
            p=Path(__file__).with_name(n+'.py');r.input_hashes[str(p)]=sha(p)
        code=r.out/'tbib_original_mmap.bin';code.write_bytes(tbib);pairs=[]
        for pattern,seed in enumerate([0,65535,0xa55a]):
            for value in [0,1,2,0x80000000,0x12345678,0xffffffff]:
                name=f'fed20_{pattern}_{value:x}';state={};initial={};calls=[];events=[];buffer_values={};asm='mov r20,sp\n'
                asm+=''.join(f'mov r{i},{i*0x01100110:#x}\n' for i in range(13,20))
                def get(a):
                    if a not in state:state[a]=(seed^(a>>2))&65535;initial[a]=state[a]
                    return state[a]
                def emit(pc,op,a,v):
                    get(a);events.append((pc,op,a,v))
                    if op=='write':state[a]=v
                for e,kind,a,bit in SPECS:
                    argv=[value];ret=None;ret1=None;start=len(events)
                    if kind in ['toggle','inverse_toggle']:
                        on=(value!=0)^(kind=='inverse_toggle');rd,wr=(20,28) if value else (36,44)
                        emit(e+rd,'read',a,get(a));emit(e+wr,'write',a,(get(a)&~(1<<bit))|((1<<bit) if on else 0))
                    elif kind=='set':
                        emit(e+12,'read',a,get(a));emit(e+20,'write',a,get(a)|(1<<bit))
                    elif kind=='masked_split':
                        emit(e+16,'read',a,get(a));emit(e+40,'write',a,(get(a)&15)|(value&0xfff0));emit(e+56,'write',a+4,value>>16)
                    elif kind=='split':emit(e+16,'write',a,value&65535);emit(e+32,'write',a+4,value>>16)
                    elif kind=='store':emit(e+12,'write',a,value&65535)
                    elif kind in ['read','bit']:
                        emit(e+12,'read',a,get(a));ret=get(a) if kind=='read' else (get(a)>>bit)&1
                    elif kind=='pair_to_RAM':
                        argv=[0x700000,0x700004];emit(e+20,'read',a,get(a));emit(e+36,'read',a+4,get(a+4))
                        buffer_values={0x700000:get(a+4),0x700004:get(a)}
                    elif kind in ['or_mask','clear_mask']:
                        emit(e+16,'read',a,get(a));n=(get(a)|value) if kind=='or_mask' else (get(a)&~value)
                        emit(e+(26 if kind=='or_mask' else 24),'write',a,n&65535)
                    elif kind=='write48':
                        argv=[value,value^0xa5a55a5a]
                        emit(0x100352c,'read',0xfed2010,get(0xfed2010));emit(0x1003534,'write',0xfed2010,get(0xfed2010)|1)
                        emit(0x100355c,'write',0xfed2024,argv[1]&65535);emit(0x1003568,'write',0xfed2020,value>>16);emit(0x1003578,'write',0xfed201c,value&65535)
                        emit(0x1003584,'read',0xfed2014,get(0xfed2014));emit(0x1003592,'write',0xfed2014,(get(0xfed2014)&0xff00)|0xdb)
                    elif kind=='read48':
                        emit(0x10035ac,'read',a,get(a));emit(0x10035b4,'write',a,get(a)|1)
                        for pc,aa in [(0x10035c0,0xfed2024),(0x10035d0,0xfed2020),(0x10035e0,0xfed201c)]:emit(pc,'read',aa,get(aa))
                        emit(0x10035e6,'read',a,get(a));emit(0x10035ee,'write',a,get(a)&~1)
                        ret=(get(0xfed2020)<<16)|get(0xfed201c);ret1=get(0xfed2024)
                    else:raise AssertionError(kind)
                    asm+=''.join(f'mov r{i},{v:#x}\n' for i,v in enumerate(argv))+f'mov r12,{e:#x}\njl [r12]\n'
                    if ret is not None:asm+=f'cmp r0,{ret:#x}\nbne fail\n'
                    if ret1 is not None:asm+=f'cmp r1,{ret1:#x}\nbne fail\n'
                    asm+='cmp sp,r20\nbne fail\n'+''.join(f'cmp r{i},{i*0x01100110:#x}\nbne fail\n' for i in range(13,20))
                    calls.append(dict(entry=hex(e),kind=kind,address=hex(a),bit=bit,arguments=argv,return0=ret,return1=ret1,events=events[start:]))
                assert len(state)==25
                asm+='mov r0,0\nb finish\nfail:\nmov r0,7\nfinish:\nmov r8,1\ntrap_s 1\n';elf=compile_probe(r,name,asm);traces=[]
                for enabled in [False,True]:
                    run=name+('_observed' if enabled else '_reference');r.observe=enabled;fixtures={}
                    options=['--memory-mapfile','/result/'+code.name,'--memory-region',f'{base:#x},{size:#x}']
                    buf=r.out/(run+'_buffer.bin');buf.write_bytes(b'\xa5'*8);options+=['--memory-mapfile','/result/'+buf.name,'--memory-region','0x700000,8']
                    for a in sorted(state):
                        before=bytearray(b'\xa5'*8);struct.pack_into('<H',before,a%8,initial[a]);p=r.out/f'{run}_{a:x}.bin';p.write_bytes(before)
                        fixtures[hex(a)]=dict(file=p.name,before=before.hex());options+=['--memory-mapfile','/result/'+p.name,'--memory-region',f'{a:#x},2']
                    r.range_override=known_sections(elf,False)+f',{base:#x}:{size:#x}'
                    c,log=r.run(run,'/result/'+elf.name,options,trace=True,extract=True)
                    assert c['exit_code']==0 and c['fault'] is None,(run,log[-3000:])
                    assert not any(x in log for x in ['S33_UNDEFINED','S33_AUX_UNKNOWN','S33_DSP_LAB','runtime error:'])
                    raw=[json.loads(line.removeprefix('S33_MEM ')) for line in (r.out/(run+'.stderr.log')).read_text().splitlines() if line.startswith('S33_MEM ')]
                    done=[x for x in raw if x['stage']=='result'];assert len(raw)==2*len(done) and all(x['width_bytes']==2 for x in raw)
                    assert [(x['pc'],x['operation'],x['address'],x['value']) for x in done]==(events if enabled else [])
                    for key,f in fixtures.items():
                        a=int(key,0);off=a%8;after=(r.out/f['file']).read_bytes();before=bytes.fromhex(f['before'])
                        assert struct.unpack_from('<H',after,off)[0]==state[a] and all(after[j]==before[j] for j in range(8) if j not in [off,off+1]);f['after']=after.hex()
                    expected_buffer=bytearray(b'\xa5'*8)
                    for a,v in buffer_values.items():struct.pack_into('<H',expected_buffer,a-0x700000,v)
                    assert buf.read_bytes()==expected_buffer and code.read_bytes()==tbib
                    c.update(pattern=pattern,seed=seed,value=value,observer_enabled=enabled,original_calls=calls,completed_memory_events=done,
                        fixtures=fixtures,buffer_file=buf.name,buffer_expected=expected_buffer.hex(),original_calls_completed=True)
                    traces.append((r.out/(run+'.trace')).read_bytes());print(run,'PASS',len(done),'events',flush=True)
                assert traces[0]==traces[1];pairs.append(dict(name=name,events=len(events),trace_identical=True))
        assert all(sha(PARENT/k)==v for k,v in ledger.items())
        r.results.update(status='PASS_ORIGINAL_TBIB_FED20_ACCESSORS',parent_atlas=str(PARENT),pairs=pairs,specs=SPECS,
            payload=dict(base=base,size=size,path=str(code),sha256=sha(code),firmware_offset=0x7c,checksum=checksum),
            hardware_access=False,gnu_modified=False,full_TBIB_boot_proven=False,
            limits=['31original routines completed for18fixture scenarios;not fullTBIB boot,globalreachability,allargumentdomains orphysicalreset.',
                'OriginalTBIB bytes mapped unchanged;global linearOOBguard remains intact;no firmwarepadding ortruncation.',
                'MMIOseeds/backing,stack andRAMoutputbuffer aredeclaredfixtures;physicalperipheralnames/permissions/timing/IRQ/latching unknown.',
                '48bittransport issoftwareordering/dataflow,not proof ofhardwarecapture atomicity orsnapshot.'])
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
