#!/usr/bin/env python3
"""Check C wire replies against Python, on host and the pinned GNU ARC700 CPU."""
from datetime import datetime,timezone
from pathlib import Path
import json,subprocess,sys,struct,hashlib,shutil
from types import SimpleNamespace
from akeru_ramdump import frame,decode,SimulatedDevice
from s33_run_gnu_arc700 import LEGACY,TOOLCHAIN,Runner,sha as file_sha,elf_loads
ROOT=Path(__file__).resolve().parents[1]


def sha(data):return hashlib.sha256(data).hexdigest()


def verify_gnu(out,obj,vectors,replies,sources):
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,
        output=out/'gnu',action='akeruram-c-service'))
    try:
        r.prepare()
        r.results.update(assumptions=['Isolated C service ELF with explicit laboratory stack',
            'Synthetic RAM callback and map; no Nikon USB, DMA, IRQ or MMIO'],
            limits=['CPU execution of protocol core, not complete firmware boot or hardware verification'],
            hardware_tested=False,installable=False)
        for p in sources+[obj,Path(shutil.which('arc-snps-elf-gcc')).resolve()]:
            r.input_hashes[str(p)]=file_sha(p)
        def command(name,args):
            p=r.command(name,args)
            assert p.returncode==0,p.stdout
            return p.stdout
        def array(data):return ','.join(str(b) for b in data)
        offsets=[];at=0
        for reply in replies:offsets.append(at);at+=len(reply)
        (r.out/'usb_ram_vectors.h').write_text(
            'static const uint8_t requests[18][32]={'+','.join('{'+array(v)+'}' for v in vectors)+'};\n'+
            'static const uint8_t replies[]={'+array(b''.join(replies))+'};\n'+
            'static const uint32_t reply_sizes[]={'+','.join(str(len(v)) for v in replies)+'};\n'+
            'static const uint32_t reply_offsets[]={'+','.join(map(str,offsets))+'};\n')
        command('compile_test',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls',
            '-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-DAKERU_GNU_TEST',
            '-I'+str(ROOT/'AkeruOS'),'-I'+str(r.out),'-c',ROOT/'AkeruOS/tests/usb_ram_test.c',
            '-o',r.out/'test.o'])
        (r.out/'start.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            ' mov sp,_stack_top\n bl main\n mov r8,1\n trap_s 1\n'
            '.global test_fail\ntest_fail:\n mov r8,1\n trap_s 1\n'
            '.section .stack,"aw",@nobits\n.align 16\n.space 16384\n_stack_top:\n')
        command('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL',
            '-o',r.out/'start.o',r.out/'start.s'])
        elf=r.out/'core_test.elf'
        command('link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld',
            '-o',elf,r.out/'start.o',r.out/'test.o',obj])
        assert not command('undefined',['arc-snps-elf-nm','-u',elf]).strip()
        command('disassembly',[TOOLCHAIN/'arc-elf32-objdump','-d','-m','arc:ARC700','-EL',elf])
        r.results['service_elf_entry'],segments=elf_loads(elf)
        assert r.results['service_elf_entry']==0x1000
        r.results['service_elf_segments']=[{k:v for k,v in s.items() if k!='data'} for s in segments]
        case,text=r.run('wire_and_guards','/result/core_test.elf')
        assert case['exit_code']==0 and case['fault'] is None,text
        assert case['instructions']>1000
        r.finish()
        r.results.update(status='PASS_GNU_ARC700_C_AKERURAM_EXECUTION',wire_cases=18,
            invalid_cases=10,read_callbacks=4,cross_language_exact_replies=True)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    return dict(evidence=str((r.out/'verified_evidence.json').relative_to(ROOT)),
        instructions=case['instructions'],simulator_sha256=r.results['simulator_sha256'])


def main():
    out=ROOT/'Risultati/AkeruUSB_RAM_Debug/Core'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True,exist_ok=False);print('Evidence:',out,flush=True)
    sources=[Path(__file__),ROOT/'AkeruOS/usb_ram.c',ROOT/'AkeruOS/usb_ram.h',
        ROOT/'AkeruOS/ram_dump.h',ROOT/'AkeruOS/tests/usb_ram_test.c',ROOT/'Python_Trace_Scripts/akeru_ramdump.py']
    hashes={str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources}
    for p in sources:(out/(p.name+'.snapshot')).write_bytes(p.read_bytes())

    def command(name,args):
        (out/(name+'.command.json')).write_text(json.dumps([str(x) for x in args],indent=2)+'\n')
        r=subprocess.run([str(x) for x in args],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
        (out/(name+'.log')).write_text(r.stdout);assert r.returncode==0,r.stdout[-4000:]
        return r.stdout

    vectors=[]
    requests=[(1,0,0),(2,0,0),(3,0x1000,1),(3,0x1000,4096),(3,0x2000,4096),
        (3,0x8000,513),(3,0x1000,0),(3,0x1000,4097),(3,0xfff,2),(3,0xffffffff,2),
        (3,0xfe00000,1),(3,0x7000,1),(4,0,0),(6,0,0),(1,1,0),(5,0,0),(3,0x1000,1),(4,0,0)]
    for seq,(op,address,length) in enumerate(requests,1):vectors.append(frame(op,seq,address,length))
    request_file=out/'requests.bin';request_file.write_bytes(b''.join(vectors))
    host=out/'core_test'
    command('host_compile',['cc','-std=c11','-Wall','-Wextra','-Werror','-g',
        '-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(ROOT/'AkeruOS'),
        sources[1],sources[4],'-o',host])
    log=command('host_test',[host,request_file,out/'responses.bin'])
    assert log.strip()=='PASS c_wire_cases=18 invalid_cases=10 read_callbacks=4',log
    device=SimulatedDevice();device.epoch=bytes(range(1,17));device.fail_address=0x2000
    data=(out/'responses.bin').read_bytes();at=0;replies=[];expected_replies=[]
    for request in vectors:
        size=struct.unpack_from('<I',data,at)[0];at+=4
        actual=data[at:at+size];at+=size
        assert actual==device.handle(request),(decode(request),decode(actual))
        expected_replies.append(actual)
        replies.append(dict(request=decode(request)[:5],response=decode(actual)[:5],bytes=size))
    assert at==len(data)
    obj=out/'usb_ram_arc700.o'
    command('arc_compile',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2',
        '-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-c',sources[1],'-o',obj])
    assert not command('arc_undefined',['arc-snps-elf-nm','-u',obj]).strip()
    assert 'R_ARC_SDA_' not in command('arc_disassembly',['arc-snps-elf-objdump','-dr',obj])
    size=command('arc_size',['arc-snps-elf-size',obj]).splitlines()[1].split()
    assert int(size[1])==int(size[2])==0
    gnu=verify_gnu(out,obj,vectors,expected_replies,sources)
    assert all(sha((ROOT/p).read_bytes())==value for p,value in hashes.items())
    result=dict(status='PASS_C_AKERURAM_WIRE_SERVICE_HOST_AND_GNU_ARC700',wire_cases=18,
        invalid_cases=10,cross_language_exact_replies=True,arc_text_bytes=int(size[0]),data=0,bss=0,
        unresolved_symbols=[],sources=hashes,replies=replies,gnu=gnu,hardware_tested=False,installable=False,
        limits=['Host C ASan/UBSan plus actual GNU ARC700 CPU execution, not original USB driver binding',
            'RAM callback supplies synthetic pattern or explicit read failure; no physical Nikon map provided',
            'Single-task complete-frame service only; transport framing/endpoint ownership/worker/cancel and dedicated initializer remain unbound',
            'Epoch and full-map flags supplied by platform; valid numerical ranges do not prove physical readability; NON_INSTALLARE'])
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
    print(result['status'],out)


if __name__=='__main__':main()
