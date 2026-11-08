#!/usr/bin/env python3
"""Verify Load Later event consumers with original bit APIs and bounded fixtures.

No scheduler or hardware: kernel/empty wait lists are explicit laboratory data.
The wait and two outside services are recording stubs. Separate predicate tests
execute only the original decision slice, intercepted before either continuation.
"""
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime,timezone
import hashlib,json,re,struct,sys
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe
sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
from static_common import BS,PS,raw,u32,locate,disasm,cstring

REC=0x373c38;BITS=REC+36;AUTO=REC+40;CALLBACK=0x365614
CURRENT=0x2000000;STATES=0x2001000;KERNEL=0x2040000;TASK=0x2041000;READY=0x2042000
HANDLE=0x42700002;MAGIC=0x45564e4c
WINDOWS=[(0xc5718,0xc577c),(0xc578c,0xc57d2),(0xc57d8,0xc57f6),
 (0xc57f8,0xc5830),(0xc5830,0xc586a),(0xc5870,0xc588c),(0xc588c,0xc58c8),
 (0x134ef4,0x134f10),(0x158c30,0x158cbc),(0x158cbc,0x158d04),
 (0x158d04,0x158e1e),(0x158e28,0x158e48),(0x23c758,0x23c8ac),
 (0x23c8ac,0x23c902),(0xb2d34,0xb2d50),(0x2c9994,0x2c9a28),
 (0x1eb270,0x1eb280),(0x1eb3c8,0x1eb3d8),(0x659c28,0x659c38),
 (0xc5c02,0xc5c10),(0xc5e8c,0xc5e9e),(0xc58c8,0xc58f4)]


def main():
    out=ROOT/'Risultati/Dump_fotocamera/Eventi_Caricamento'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='load-later-event-consumers'))
    print('Evidence:',out,flush=True)
    try:
        r.prepare()
        previous=ROOT/json.loads((ROOT/'Risultati/Dump_fotocamera/Gruppi_Caricamento/latest.json').read_text())['evidence']
        old=json.loads(previous.read_text());assert old['status']=='PASS_GROUP_MAPPING_AND_CONDITIONAL_PROTOCOL'
        for p,h in old['input_hashes'].items():assert sha(Path(p))==h,p;r.input_hashes[p]=h
        r.input_hashes[str(previous)]=sha(previous)
        for p in [ROOT/'work/build-arc/binutils'/n for n in ('objcopy','objdump')]:r.input_hashes[str(p)]=sha(p)
        main=(ROOT/'DUMPS/MainCode.dmp').read_bytes();spans=[]
        def span(a,n):
            b,o=locate(a,n);d=raw(a,n);assert main[b['offset']+o:b['offset']+o+n]==d,(hex(a),n)
            spans.append(dict(address=hex(a),bytes=n,sha256=hashlib.sha256(d).hexdigest()))
        listings=[]
        for a,b in WINDOWS:span(a,b-a);listings.append(disasm(a,b))
        (out/'gnu_verified.txt').write_text('\n'.join(listings))
        table=[struct.unpack('<14I',raw(0x372a48+56*i,56)) for i in range(85)]
        index=(REC-0x372a48)//56;assert index==82 and table[index]==(MAGIC,HANDLE,2)+tuple([0]*11)
        span(REC,56);span(0x3729c8,32);span(0x3766d2,11)
        assert [u32(0x3729c8+4*i) for i in range(5)]==[0x42700001,0xc5830,0x2800,0x13,0x3766d2]
        assert cstring(0x3766d2)=='Load Later'
        pools={0xc577c:CALLBACK,0xc5780:HANDLE,0xc5784:0x158ce0,0xc5788:0x42700001,
               0xc57d4:HANDLE,0xc586c:HANDLE,0x1350bc:HANDLE,0x1350c0:0x13574c,0x1350c4:0x135760}
        for p,v in pools.items():span(p,4);assert u32(p)==v
        # Full payload byte search is only an inventory of literal candidates.
        literals=[]
        for b in BS:
            data=PS[b['index']];start=0
            while (at:=data.find(struct.pack('<I',HANDLE),start))>=0:
                literals.append(dict(block=b['index'],address=hex(b['load_address_candidate']+at)));start=at+1
        assert len(literals)==7
        base0=BS[0]['load_address_candidate'];base1=BS[1]['load_address_candidate']
        assert (base0,base1)==(0xad800,0x360800)
        image0=bytearray(PS[0]);image1=bytearray(PS[1]);patches=[];stubmaps=[]
        def binary(name,source):
            elf=compile_probe(r,name,source);p=out/(name+'.bin')
            proc=r.command(name+'_extract',[TOOLCHAIN/'arc-elf32-objcopy','-O','binary','--only-section=.text',elf,p]);assert proc.returncode==0
            return p
        def stub(name,address,source):
            p=binary(name,source);d=p.read_bytes();p.write_bytes(d+b'\0'*(8+(-len(d))%8))
            assert len(p.read_bytes())<0x200
            stubmaps.extend(['--memory-mapfile',f'/result/{p.name}','--memory-region',f'{address:#x},{len(p.read_bytes())}'])
        def patch(image,name,target,dest):
            p=binary('entry_'+name,f' mov_s r12,{dest:#x}\n j_s [r12]\n');d=p.read_bytes();assert len(d)==8
            at=target-base0;patches.append(dict(name=name,address=hex(target),destination=hex(dest),original=image[at:at+8].hex(),replacement=d.hex()))
            image[at:at+8]=d
        head=f' mov r10,{CURRENT:#x}\n ld r10,[r10]\n'
        wait=(head+' ld r9,[r10,20]\n add r9,r9,1\n st r9,[r10,20]\n'
              ' st r0,[r10,24]\n st r1,[r10,28]\n st r2,[r10,32]\n st r3,[r10,36]\n ld r0,[r10]\n j_s [blink]\n')
        other=(head+' ld r9,[r10,40]\n add r9,r9,1\n st r9,[r10,40]\n st r0,[r10,44]\n st r1,[r10,48]\n')
        stub('wait_record',0x2030000,wait)
        stub('other_record',0x2030200,other+' mov r0,0\n j_s [blink]\n')
        stub('partial_continuation',0x2030400,other+' ld r12,[r10,64]\n j_s [r12]\n')
        for n,a,d in [('wait',0x158d04,0x2030000),('other',0x158e78,0x2030200),('partial',0xd3e38,0x2030400)]:patch(image0,n,a,d)
        # Original event set/clear/query/resolver and consumer windows are untouched.
        for a,b in [(0x158c8c,0x158d04),(0x158e28,0x158e48),(0xc5718,0xc58c8),
                    (0x23c758,0x23c902),(0x134ef4,0x134f08)]:assert image0[a-base0:b-base0]==raw(a,b-a)
        (out/'main0_consumers_fixture_NOT_FIRMWARE.bin').write_bytes(image0)
        (out/'main1_lab_input.bin').write_bytes(image1);(out/'main1_lab_mmap.bin').write_bytes(image1)
        # Explicit empty-list/nested-lock kernel fixture. No scheduler is entered:
        # the ready-head points to the current task so B2D34 returns normally.
        k=bytearray(0x800);struct.pack_into('<I',k,28,TASK);struct.pack_into('<I',k,44,READY)
        t=bytearray(0x100);struct.pack_into('<I',t,104,1)
        for name,data in [('kernel',k),('task',t),('ready',struct.pack('<II',TASK,TASK)),('current',bytes(8))]:(out/(name+'.bin')).write_bytes(data)
        cases=[]
        for bits in range(256):cases.append(dict(kind='reset',entry=0xc5718,bits=0xa5000000|bits,arg=0,status=0,expected=0,after=0xa5000002,callback=0,waits=0,other=1))
        for entry,mask in [(0xc57f8,2),(0xc588c,128)]:
            for bits in range(256):cases.append(dict(kind='poll',entry=entry,bits=0xa5000000|bits,arg=0,status=0,expected=int(bool(bits&mask)),after=0xa5000000|bits,callback=0x12345678,waits=0,other=0))
            for config in ('uninitialized','invalid_magic'):
                cases.append(dict(kind='poll',entry=entry,bits=0xffffffff,arg=0,status=0,expected=0,after=0xffffffff,callback=0x12345678,waits=0,other=0,config=config))
        statuses=(0,0x200304,0x345)
        for arg in (0,0x2031000,0x2031200):
            for status in statuses:cases.append(dict(kind='request',entry=0xc578c,bits=0xa50000fe,arg=arg,status=status,expected=int(bool(arg)),after=0xa50000fd if arg else 0xa50000fe,callback=arg if arg else 0x12345678,waits=int(bool(arg)),other=0,mask=2))
        for entry,mask in [(0xc57d8,2),(0xc5870,128)]:
            for status in statuses:cases.append(dict(kind='wait',entry=entry,bits=0xa50000fe,arg=0,status=status,expected=int(status==0),after=0xa50000fe,callback=0x12345678,waits=1,other=0,mask=mask))
        for status in statuses:cases.append(dict(kind='partial_prefix',entry=0x134ef4,bits=8,arg=0,status=status,after=8,callback=0x12345678,waits=1,other=1,mask=8))
        assert len(cases)==790
        states=bytearray(len(cases)*128);asm=f' mov r20,{CURRENT:#x}\n mov r0,{KERNEL:#x}\n mov r1,0x369348\n st r0,[r1]\n'
        for i,c in enumerate(cases):
            address=STATES+i*128;struct.pack_into('<I',states,i*128,c['status'])
            flags=2 if c.get('config')=='uninitialized' else 0x80000002
            magic=0 if c.get('config')=='invalid_magic' else MAGIC
            asm+=(f' mov r21,{address:#x}\n st r21,[r20]\n mov r0,{flags:#x}\n mov r1,{REC+8:#x}\n st r0,[r1]\n'
                  f' mov r0,{magic:#x}\n mov r1,{REC:#x}\n st r0,[r1]\n mov r0,{c["bits"]:#x}\n mov r1,{BITS:#x}\n st r0,[r1]\n'
                  f' mov r0,0x12345678\n mov r1,{CALLBACK:#x}\n st r0,[r1]\n')
            if c['kind']=='partial_prefix':
                asm+=f' mov r0,resume_{i}\n st r0,[r21,64]\n mov r12,{c["entry"]:#x}\n j_s [r12]\nresume_{i}:\n'
            else:asm+=f' mov r0,{c["arg"]:#x}\n mov r12,{c["entry"]:#x}\n jl [r12]\n st r0,[r21,4]\n'
            asm+=(f' mov r1,{BITS:#x}\n ld r0,[r1]\n st r0,[r21,12]\n mov r1,{CALLBACK:#x}\n ld r0,[r1]\n st r0,[r21,52]\n')
        asm+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        (out/'states_input.bin').write_bytes(states);(out/'states_mmap.bin').write_bytes(states)
        def mmap(name,address,size):return ['--memory-mapfile',f'/result/{name}','--memory-region',f'{address:#x},{size}']
        common=(mmap('main1_lab_mmap.bin',base1,len(image1))+mmap('current.bin',CURRENT,8)+mmap('kernel.bin',KERNEL,len(k))+
                mmap('task.bin',TASK,len(t))+mmap('ready.bin',READY,8)+stubmaps)
        elf=compile_probe(r,'consumer_protocol',asm)
        opts=mmap('main0_consumers_fixture_NOT_FIRMWARE.bin',base0,len(image0))+mmap('states_mmap.bin',STATES,len(states))+common
        case,log=r.run('consumer_protocol',f'/result/{elf.name}',opts,trace=True)
        assert case['exit_code']==0 and case['fault'] is None,log
        got=(out/'states_mmap.bin').read_bytes()
        for i,c in enumerate(cases):
            w=struct.unpack_from('<32I',got,i*128)
            if c['kind']!='partial_prefix':assert w[1]==c['expected'],(i,c,w)
            assert (w[3],w[13],w[5],w[10])==(c['after'],c['callback'],c['waits'],c['other']),(i,c,w)
            if c['waits']:assert w[6:10]==(HANDLE,c['mask'],0,0),(i,c,w)
            if c['kind']=='partial_prefix':assert w[11:13]==(0x13574c,0x135760),(i,c,w)
            if c['kind']=='reset':assert w[11:13]==(0x42700001,0),(i,c,w)
            c.update(observed_return=w[1] if c['kind']!='partial_prefix' else None,observed_after=w[3],observed_callback=w[13])
        (out/'consumer_cases.json').write_text(json.dumps(cases,indent=2)+'\n')
        after1=(out/'main1_lab_mmap.bin').read_bytes()
        allowed={a-base1+i for a in (0x369348,REC,REC+8,BITS,CALLBACK) for i in range(4)}
        changed=[i for i,(a,b) in enumerate(zip(image1,after1)) if a!=b]
        assert set(changed)<=allowed
        for name,data0 in [('kernel',k),('task',t),('ready',struct.pack('<II',TASK,TASK))]:assert (out/(name+'.bin')).read_bytes()==data0
        # Execute one actual Load Later iteration, then stop at the second wait.
        # This preserves the loop and adjacent literal pool atC586C unchanged.
        taskwait=(head+' ld r9,[r10,20]\n add r9,r9,1\n st r9,[r10,20]\n'
                  ' st r0,[r10,24]\n st r1,[r10,28]\n st r2,[r10,32]\n st r3,[r10,36]\n'
                  ' cmp r9,2\n beq task_done\n ld r0,[r10]\n j_s [blink]\ntask_done:\n mov r0,0\n mov r8,1\n trap_s 1\n')
        stub('task_wait_record',0x2030a00,taskwait)
        stub('task_callback',0x2031000,head+' ld r9,[r10,72]\n add r9,r9,1\n st r9,[r10,72]\n j_s [blink]\n')
        taskimage=bytearray(image0);patch(taskimage,'task_wait',0x158d04,0x2030a00)
        assert taskimage[0xc5830-base0:0xc586a-base0]==raw(0xc5830,58)
        (out/'main0_task_fixture_NOT_FIRMWARE.bin').write_bytes(taskimage)
        task_results=[]
        for i,(callback,status) in enumerate((c,s) for c in (0,0x2031000) for s in statuses):
            state=bytearray(128);struct.pack_into('<I',state,0,status)
            statefile=f'task_loop_{i}_state.bin';mainfile=f'task_loop_{i}_main1.bin'
            (out/statefile).write_bytes(state);(out/mainfile).write_bytes(image1)
            source=(f' mov r0,{STATES:#x}\n mov r1,{CURRENT:#x}\n st r0,[r1]\n'
                    f' mov r0,{KERNEL:#x}\n mov r1,0x369348\n st r0,[r1]\n'
                    f' mov r0,0x80000002\n mov r1,{REC+8:#x}\n st r0,[r1]\n'
                    f' mov r0,0xa50000fd\n mov r1,{BITS:#x}\n st r0,[r1]\n'
                    f' mov r0,{callback:#x}\n mov r1,{CALLBACK:#x}\n st r0,[r1]\n'
                    ' mov r0,0\n mov r12,0xc5830\n j_s [r12]\n')
            elf=compile_probe(r,f'task_loop_{i}',source)
            opts=(mmap('main0_task_fixture_NOT_FIRMWARE.bin',base0,len(taskimage))+mmap(mainfile,base1,len(image1))+
                  mmap(statefile,STATES,128)+mmap('current.bin',CURRENT,8)+mmap('kernel.bin',KERNEL,len(k))+
                  mmap('task.bin',TASK,len(t))+mmap('ready.bin',READY,8)+stubmaps)
            taskcase,log=r.run(f'task_loop_{i}',f'/result/{elf.name}',opts,trace=True)
            assert taskcase['exit_code']==0 and taskcase['fault'] is None,log
            w=struct.unpack('<32I',(out/statefile).read_bytes());m=(out/mainfile).read_bytes()
            assert w[5]==2 and w[6:10]==(HANDLE,1,0,0) and w[18]==int(bool(callback)),(i,w)
            assert struct.unpack_from('<I',m,BITS-base1)[0]==0xa50000fe
            assert struct.unpack_from('<I',m,CALLBACK-base1)[0]==callback
            task_results.append(dict(callback=hex(callback),wait_status=hex(status),wait_calls=2,callback_calls=w[18],after_bits='0xA50000FE',stopped_at_second_wait=True))
        (out/'task_loop_cases.json').write_text(json.dumps(task_results,indent=2)+'\n')
        # Original group orchestrator plus original bit publication: every I/O,
        # lock and profiling service is stubbed. Inject one failed read by offset.
        readstub=(head+' ld r9,[r10,80]\n add r9,r9,1\n st r9,[r10,80]\n'
                  ' ld r11,[r10,76]\n cmp r0,r11\n bne read_ok\n'
                  ' ld r9,[r10,84]\n add r9,r9,1\n st r9,[r10,84]\n mov r0,0\n j_s [blink]\n'
                  'read_ok:\n mov r0,1\n j_s [blink]\n')
        stub('group_read',0x2031400,readstub);stub('group_service_zero',0x2031600,' mov r0,0\n j_s [blink]\n')
        groupimage=bytearray(image0)
        for name,target in [('profile',0x12cad4),('lock',0x1593ac),('configure',0x159550),('unlock',0x1594a4),('phase',0x159128)]:
            patch(groupimage,'group_'+name,target,0x2031600)
        patch(groupimage,'group_read',0x159558,0x2031400)
        (out/'main0_groups_fixture_NOT_FIRMWARE.bin').write_bytes(groupimage)
        (out/'groups_main1_mmap.bin').write_bytes(image1)
        failures=[(None,0xffffffff,0xfc,7),(2,0x376600,0xf8,6),(3,0x3e0400,0xf8,7),
                  (4,0x4fb600,0xe4,6),(5,0x5fb800,0xec,7),(9,0x8c9a00,0xfc,7),
                  (6,0x707600,0x9c,6),(7,0x8c2a00,0xbc,7)]
        groupstates=bytearray(128*len(failures));source=(f' mov r0,{KERNEL:#x}\n mov r1,0x369348\n st r0,[r1]\n'
                  f' mov r0,0x80000002\n mov r1,{REC+8:#x}\n st r0,[r1]\n')
        for i,(_,offset,_,_) in enumerate(failures):
            struct.pack_into('<I',groupstates,i*128+76,offset);state=STATES+i*128
            source+=(f' mov r21,{state:#x}\n mov r1,{CURRENT:#x}\n st r21,[r1]\n'
                     f' mov r0,0\n mov r1,{BITS:#x}\n st r0,[r1]\n mov r1,0x365618\n st r0,[r1]\n'
                     ' mov r0,0x10\n mov r1,0x928\n stb r0,[r1]\n mov r12,0xc58c8\n jl [r12]\n'
                     f' st r0,[r21,4]\n mov r1,{BITS:#x}\n ld r0,[r1]\n st r0,[r21,12]\n')
        source+=' mov r0,0\n mov r8,1\n trap_s 1\n'
        (out/'groups_states_input.bin').write_bytes(groupstates);(out/'groups_states_mmap.bin').write_bytes(groupstates)
        elf=compile_probe(r,'group_failures',source)
        opts=(mmap('main0_groups_fixture_NOT_FIRMWARE.bin',base0,len(groupimage))+mmap('groups_main1_mmap.bin',base1,len(image1))+
              mmap('groups_states_mmap.bin',STATES,len(groupstates))+mmap('current.bin',CURRENT,8)+mmap('kernel.bin',KERNEL,len(k))+
              mmap('task.bin',TASK,len(t))+mmap('ready.bin',READY,8)+stubmaps)
        groupcase,log=r.run('group_failures',f'/result/{elf.name}',opts,trace=True)
        assert groupcase['exit_code']==0 and groupcase['fault'] is None,log
        got=(out/'groups_states_mmap.bin').read_bytes();group_results=[]
        for i,(index,offset,expected,reads) in enumerate(failures):
            w=struct.unpack_from('<32I',got,i*128)
            assert w[1]==0 and w[3]==expected and w[20]==reads and w[21]==int(index is not None),(i,w)
            group_results.append(dict(failed_payload=index,failed_offset=hex(offset) if index is not None else None,
                                      observed_bits=hex(w[3]),read_calls=w[20],failed_reads=w[21],wrapper_return=w[1]))
        (out/'orchestrator_cases.json').write_text(json.dumps(group_results,indent=2)+'\n')
        # Original predicate/control-flow slice: stop before queuing or return
        # continuation. Configured auto-clear0 plus diagnostic auto-clear1.
        predimage=bytearray(image0)
        stub('predicate_yes',0x2030600,' mov r0,1\n j_s [blink]\n')
        stub('predicate_no',0x2030800,' mov r0,0\n j_s [blink]\n')
        patch(predimage,'matched_boundary',0x2c9a08,0x2030600);patch(predimage,'queue_boundary',0x2c9a28,0x2030800)
        assert predimage[0x2c99e0-base0:0x2c9a08-base0]==raw(0x2c99e0,40)
        (out/'main0_predicate_fixture_NOT_FIRMWARE.bin').write_bytes(predimage)
        predicates=[]
        for auto in (0,1):
            for bits in range(256):
                for mask in (8,128,136):
                    for option in (0,1):predicates.append((bits,mask,option,auto))
        data=bytearray()
        for bits,mask,option,auto in predicates:data+=struct.pack('<6I',bits,mask,option,auto,0xdeadbeef,0xdeadbeef)
        (out/'predicate_input.bin').write_bytes(data);(out/'predicate_mmap.bin').write_bytes(data)
        obj=0x2050000;tablebase=0x2051000;(out/'predicate_object.bin').write_bytes(bytes(64))
        source=(f' mov r20,{tablebase:#x}\n mov r21,{len(predicates)}\n mov r22,{obj:#x}\nloop_pred:\n'
            ' ld r0,[r20]\n st r0,[r22,24]\n ld r0,[r20,12]\n st r0,[r22,28]\n mov r13,r22\n'
            ' ld r1,[r20,4]\n ld r2,[r20,8]\n mov r12,0x2c99e0\n jl [r12]\n st r0,[r20,16]\n'
            ' ld r0,[r22,24]\n st r0,[r20,20]\n add r20,r20,24\n sub.f r21,r21,1\n bne loop_pred\n mov r0,0\n mov r8,1\n trap_s 1\n')
        elf=compile_probe(r,'predicate_protocol',source)
        opts=mmap('main0_predicate_fixture_NOT_FIRMWARE.bin',base0,len(predimage))+mmap('predicate_mmap.bin',tablebase,len(data))+mmap('predicate_object.bin',obj,64)+stubmaps
        predcase,log=r.run('predicate_protocol',f'/result/{elf.name}',opts,trace=True)
        assert predcase['exit_code']==0 and predcase['fault'] is None,log
        got=(out/'predicate_mmap.bin').read_bytes()
        for i,(bits,mask,option,auto) in enumerate(predicates):
            words=struct.unpack_from('<6I',got,i*24);yes=(bits&mask)==mask if option else bool(bits&mask)
            assert words[:4]==(bits,mask,option,auto)
            assert words[4:]==(int(yes),bits&~mask if yes and auto else bits),(i,words)
        # All original instruction PCs (not stubs) are anchored to supplied Main.
        excluded=[int(p['address'],16) for p in patches];pcs=set()
        for tracefile in [out/'consumer_protocol.trace',out/'predicate_protocol.trace',out/'group_failures.trace']+[out/f'task_loop_{i}.trace' for i in range(6)]:
            trace=tracefile.read_text();assert not re.search(r'\b(?:ld|st)\w*\.di\b',trace)
            for m in re.finditer(r'^0x([0-9a-f]+)\s',trace,re.M):
                pc=int(m[1],16)
                if base0<=pc<base0+len(image0) and not any(a<=pc<a+8 for a in excluded):pcs.add(pc)
        for pc in sorted(pcs):span(pc,8)
        assert len(pcs)>150
        assert (out/'main0_consumers_fixture_NOT_FIRMWARE.bin').read_bytes()==image0
        assert (out/'main0_predicate_fixture_NOT_FIRMWARE.bin').read_bytes()==predimage
        assert (out/'states_input.bin').read_bytes()==states and (out/'predicate_input.bin').read_bytes()==data
        (out/'laboratory_patches.json').write_text(json.dumps(patches,indent=2)+'\n')
        (out/'executed_original_pcs.json').write_text(json.dumps([hex(p) for p in sorted(pcs)],indent=2)+'\n')
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_LOAD_EVENT_CONSUMERS_AND_PERSISTENT_BITS',previous_evidence=str(previous.relative_to(ROOT)),
            assumptions=['Lab kernel pointer/current task/ready head, nested lock1, empty waiter list; not camera runtime',
                         'Event active flag set explicitly in lab; configured auto-clear0; diagnostic auto-clear1 separate',
                         'Wait158D04 and services158E78/D3E38 are recording stubs; no blocking, I/O or backend executed',
                         'Predicate boundaries intercepted before match continuation/queue; not complete wait/kernel'],
            event_record=dict(index=index,address=hex(REC),flags_static=2,configured_auto_clear=0,bits_cell=hex(BITS)),
            task_record=dict(address='0x3729c8',entry='0xc5830',name='Load Later'),
            literal_candidates=literals,gnu_windows=len(WINDOWS),original_main_spans=spans,
            executed_original_unique_pcs=len(pcs),consumer_cases=len(cases),predicate_cases=len(predicates),
            task_loop_cases=len(task_results),task_iterations_completed=6,main1_changed_offsets_consumer=changed,
            orchestrator_cases=len(group_results),read_failures_injected=7,resource_failure_keeps_all_progress_bits=True,
            reset_cases=256,poll_cases=516,request_cases=9,wait_helper_cases=6,partial_consumer_cases=3,
            partial_consumer='0x134EFC waits0x08 then0x134F00 overwrites result without comparison',
            reset_clear_masks=[1,4,8,16,32,64,128],reset_set_mask=2,request_clear_mask=2,request_set_mask=1,
            limitations=['No scheduler/actual waiter wake, uninterrupted task session, I/O, cache, physical readiness or ownership proof',
                         'Literal/callsite inventories are candidate/static bounded searches, not all indirect callers',
                         'Runtime event config and whether current flags change are not read from camera',
                         'End/globalbit80 can be requested despite earlier group failure; not hardware readiness'],
            physical_boot=False,AkeruOS_functional_progress_increased=False)
        case.update(consumer_cases=len(cases),real_bit_set_clear_query=True,wait_is_stub=True)
        predcase.update(predicate_cases=len(predicates),only_original_decision_slice=True)
        groupcase.update(orchestrator_cases=len(group_results),all_io_lock_profile_services_are_stubs=True,real_event_bit_publication=True)
        r.finish()
    except Exception as exc:r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(f'PASS:{len(cases)}consumer cases;{len(predicates)}predicates;6task iterations;8orchestrator cases;{len(pcs)}original PCs; no scheduler or hardware',flush=True)


if __name__=='__main__':main()
