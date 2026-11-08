#!/usr/bin/env python3
"""Execute original FAT file callbacks through PMSD/PIO and modeled DMA on a RAM card."""
from datetime import datetime, timezone
from pathlib import Path
import json, re, struct, subprocess, sys, tempfile
from s33_trace_state_dispatch import verified_payloads, sha
ROOT = Path(__file__).resolve().parents[1]


def main(probe='ProbeDumpSDFileWrite.java', suite='RAM_Dumper_SD_File_Write'):
    blocks, payloads, _ = verified_payloads(ROOT)
    out = ROOT/'Risultati/Runtime_Kernel'/suite/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    out.mkdir(parents=True, exist_ok=False)
    scripts = ROOT/'S33-sections/analysis_ghidra/scripts'
    sources = [Path(__file__)]+[scripts/n for n in ['ProbeDumpSDFileWrite.java','ProbeDumpSDWritePartition.java','ProbeDumpSDWriteAsync.java','ProbeDumpSDReadArbitration.java','ProbeDumpSDReadStatus.java','ProbeDumpSDMutex.java','ProbeStatusRead.java']]
    if probe!='ProbeDumpSDFileWrite.java':
        sources += [scripts/probe, ROOT/'Python_Trace_Scripts/s33_verify_ram_dump_sd_file_lifecycle.py']
    inputs = {str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in sources}
    for p in sources:
        (out/(p.name+'.snapshot')).write_bytes(p.read_bytes())
    with tempfile.TemporaryDirectory(prefix='s33-sd-file-write-') as td:
        temp = Path(td)
        for i in (0,1):
            (temp/f'p{i}.bin').write_bytes(payloads[i])
        cmd = [str(ROOT/'tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless'),str(temp),'file','-import',str(temp/'p0.bin'),'-loader','BinaryLoader','-loader-baseAddr','0xad800','-processor','ARCompact:LE:32:loopfix','-noanalysis','-scriptPath',str(scripts),'-postScript',probe,str(out/'trace.txt'),str(temp/'p1.bin'),'-deleteProject']
        (out/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        r = subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=300)
        (out/'headless.log').write_text(r.stdout)
        assert r.returncode==0 and 'SCRIPT ERROR' not in r.stdout,r.stdout[-6000:]
        trace = (out/'trace.txt').read_text()
        expected_cases=17 if probe=='ProbeDumpSDFileLifecycle.java' else 13
        assert trace.endswith(f'COMPLETE cases={expected_cases}\n') and trace.count('PASS file-write ')==13
    cases = {}
    for line in trace.splitlines():
        if line.startswith('PASS file-write '):
            cases[line.split()[2]] = dict(re.findall(r'(\w+)=(\S+)',line))
    assert cases['async-timeout']['timeouts']=='81' and cases['async-timeout']['ticks']=='8100'
    assert cases['fragmented-short']['status']=='0' and cases['fragmented-short']['bytes']=='1024'
    assert cases['cache-missing']['fileError']=='1a00006' and cases['cache-missing']['status']=='0'
    lifecycle = {}
    ownership = {}
    if probe=='ProbeDumpSDFileLifecycle.java':
        for line in trace.splitlines():
            if line.startswith('LIFECYCLE '):
                lifecycle[line.split()[1]]=dict(re.findall(r'(\w+)=(\S+)',line))
        assert set(lifecycle)==set(cases)
        for name,row in lifecycle.items():
            wanted=3 if name in ['new-exclusive','new-tail','new-async'] else 2
            assert row==dict(registry='2',wrappers=f'{wanted}/{wanted}',opens=str(wanted),closes='2'),(name,row)
        for line in trace.splitlines():
            if line.startswith('PASS ownership '):
                ownership[line.split()[2]]=dict(re.findall(r'(\w+)=(\S+)',line))
        assert ownership=={
            'slots-full':dict(status='1a00032',wrappers='0/0',private='0/0',scratchFailures='0',missingVolumes='0',genericCloses='0',cardUnchanged='110'),
            'scratch-oom':dict(status='1a00006',wrappers='1/1',private='0/0',scratchFailures='1',missingVolumes='0',genericCloses='0',cardUnchanged='110'),
            'preclose-missing-volume':dict(status='ffffffff',wrappers='1/1',private='1/1',scratchFailures='0',missingVolumes='1',genericCloses='1',cardUnchanged='110'),
            'close-not-ready':dict(status='1a0000c',wrappers='1/1',private='1/0',scratchFailures='0',missingVolumes='0',genericCloses='1',cardUnchanged='110')},ownership
    bad_chains={'fragmented-short'}
    if lifecycle:
        bad_chains.update(['pio-error4','pio-error8','command-error','final-error','async-timeout','async-status4'])
    file_checks = {}
    for name,case in cases.items():
        img = (out/(name+'_partition.img')).read_bytes()
        u16 = lambda at: struct.unpack_from('<H',img,at)[0]
        u32 = lambda at: struct.unpack_from('<I',img,at)[0]
        bps,spc,res,fats,roots,total,fsz = u16(11),img[13],u16(14),img[16],u16(17),u16(19),u16(22)
        assert (bps,spc,res,fats,roots,total,fsz)==(512,2,20,1,32,110,80)
        assert len(img)==total*bps and img[510:512]==b'\x55\xaa' and u32(28)==2048
        root_lba = res+fats*fsz
        data_lba = root_lba+(roots*32+bps-1)//bps
        entry = root_lba*bps
        assert img[entry:entry+11]==b'TARGET  BIN' and img[entry+11]&0x18==0
        size,cluster = u32(entry+28),u16(entry+26)
        assert size==int(case['diskSize']) and 2<=cluster<=5
        data,chain = bytearray(),[]
        while len(data)<size and 2<=cluster<=5:
            assert 2<=cluster<=5 and cluster not in chain
            chain.append(cluster)
            at=(data_lba+(cluster-2)*spc)*bps
            data.extend(img[at:at+spc*bps])
            fat_at=res*bps+cluster+cluster//2
            pair=u16(fat_at)
            cluster=pair>>4 if cluster&1 else pair&0xfff
        if name in bad_chains:
            assert cluster==0xff7 and len(data)==(2048 if name=='fragmented-short' else 1024),(name,chain,hex(cluster))
        else:
            assert len(data)>=size and cluster>=0xff8,(name,chain,hex(cluster))
        expected=bytearray(b'\xcc'*size)
        valid=int(case['reread'])
        if name in ['command-error','async-timeout','async-status4']:
            valid=0
        elif name.startswith('pio-error'):
            valid=256
        elif name=='fragmented-short':
            valid=1280
        expected[:valid]=bytes(((k*37+11)^((k>>8)*97))&255 for k in range(valid))
        assert data[:size]==expected[:min(size,len(data))],(name,chain)
        port=(out/(name+'_port.dat')).read_bytes()
        dma=(out/(name+'_dma_model.dat')).read_bytes()
        assert len(port)==int(case['stores']) and len(dma)==int(case['dmaModelBytes'])
        if dma:
            assert name=='new-async' and dma==expected
        file_checks[name]=dict(size=size,available_file_bytes=min(size,len(data)),clusters=chain,terminal_fat_entry=hex(cluster),fat_chain_valid=cluster>=0xff8,content_sha256=sha(data[:size]),partition_sha256=sha(img),pio_bytes=len(port),pio_sha256=sha(port),modeled_dma_write_bytes=len(dma),modeled_dma_sha256=sha(dma))
    fsck = {}
    for name in ['existing-rplus','new-exclusive','new-tail','new-async']+sorted(bad_chains):
        p=out/(name+'_partition.img');before=sha(p.read_bytes())
        check=subprocess.run(['/usr/bin/fsck.fat','-n',str(p)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=30)
        (out/(name+'_fsck.txt')).write_text(check.stdout)
        assert sha(p.read_bytes())==before,'read-only fsck changed image'
        assert check.returncode!=0 and 'bad cluster' in check.stdout.lower() if name in bad_chains else check.returncode==0,(name,check.stdout)
        fsck[name]=dict(exit_code=check.returncode,log=name+'_fsck.txt',log_sha256=sha(check.stdout.encode()),image_unchanged=True)
    sys.path.insert(0,str(ROOT/'S33-sections/analysis_codex'))
    from static_common import disasm, u32
    spans = [(0x1F4958,0x1F49A4),(0x21A4B8,0x21A778),(0x21A798,0x21AA3C),(0x2A1344,0x2A1398),(0x2A0D70,0x2A0E48),
             (0x12DE3C,0x12DF00),(0x1F19E0,0x1F1B18),(0x1F1B18,0x1F1B90),
             (0x2ABCD4,0x2ABEF8),(0x2AB95C,0x2ABA94),(0x2AB6F8,0x2AB77C),
             (0x1F277C,0x1F28A4),(0x1F2484,0x1F250C),(0x1F337C,0x1F346C),
             (0x2AC438,0x2AC494),(0x2A0C14,0x2A0C60),(0x26705C,0x267066),
             (0x26706C,0x26707A),(0x2C0130,0x2C014C),(0x2C0150,0x2C015C),(0x2C0160,0x2C016A)]
    checks = {0x1F4994:';0x21a4b8',0x21A4F0:';0x2a1344',0x21A894:';0x2a0d70',0x21A9D6:';0x1f337c',0x21AA0E:';0x2a1398',
              0x21A9DE:'st_s\tr0,[sp,0x14]',0x21AA30:'st_s\tr1,[r0,0]',0x12DEC6:';0x1fa090',
              0x12DEE2:'cmp_s\tr2,r17',0x12DEE6:'mov_s\tr13,0',0x12DEEA:'ld_s\tr13,[r14,0xc]',
              0x2ABD20:';0x2a2d88',0x2ABD28:'cmp_s\tr0,0',0x2ABD30:';0x2abef2',
              0x1F33AA:'ld_s\tr0,[pcl,0x10c]',0x26705C:'sth.di\tr0,[r1]',0x26706C:'sth.di\tr13,[r0]'}
    if lifecycle:
        spans += [(0x2A3C5C,0x2A3D2C),(0x2A3D2C,0x2A3E04),(0x1F21F8,0x1F2348),
                  (0x12DBFC,0x12DD24),(0x12CE8C,0x12D000),(0x12D604,0x12D6FC),
                  (0x1F56B4,0x1F57C8),(0x1F5F24,0x1F5F4E),(0x1F615A,0x1F6188),(0x1F2348,0x1F2390)]
        checks.update({0x2A3DA2:';0x268ee4',0x2A3DB6:'st\tr23,[r0,24]',0x1F2282:';0x268ee4',
                       0x1F2292:'jl_s.d\t[r3]',0x1F2324:'jl_s.d\t[r1]',0x1F2330:';0x25980c',
                       0x12DCA4:';0x1f21f8',0x12DCBE:'st_s\tr0,[r1,0x60]',0x12D6BC:';0x1f22c0',
                       0x12D6D4:'st_s\tr0,[r1,0x60]',0x12D6D6:'st\tr0,[r16]',0x12CF22:';0x1f21f8'})
    listing=''.join(disasm(a,b) for a,b in spans)
    (out/'gnu_verified.txt').write_text(listing)
    for a,token in checks.items():
        lines = [line for line in listing.splitlines() if re.match(rf'\s*{a:x}:',line)]
        assert len(lines)==1 and token in lines[0],(hex(a),token,lines)
    assert [u32(a) for a in [0x267058,0x267068,0x2C014C,0x2C015C,0x1F34B4]]==[0xFEE050C,0xFEE0510,0xFF0002C,0xFF00030,0x1A00006]
    assert all(sha((ROOT/p).read_bytes())==h for p,h in inputs.items())
    result = dict(status='PASS_ORIGINAL_FAT_FILE_WRITE_PIO_AND_MODELED_DMA_COLD_REOPEN_AND_EXPECTED_ERRORS',cpu_cases=expected_cases,returned_cases=expected_cases,cases=cases,independent_file_checks=file_checks,read_only_fsck=fsck,gnu_windows=len(spans),instruction_checks=len(checks),sources=inputs,payload_hashes={str(b['index']):b['sha256'] for b in blocks},trace=trace,
        original_bodies=['1F43AC open callback and2A1648/2AC2B4/2ABCD4 exclusive create with original lookup/guard',
            '12DE3C upper write,1F1A8C B volume resolution,1F1B18 cached status and original volume semaphore',
            '1FA090/1F4958/21A4B8 file write,1F337C metadata cache,2AB770/2AB95C cluster allocation and1F277C FAT updates',
            '2A0D70/2A0C14 cluster/sector write,PMSD/DEVSD,motors/commands/control andPIO source loads/port stores',
            'Aligned selector1 write and FAT read service/resources/status/dispatch/events/deadlines/release',
            '1F48A4/21AD30 dirty close,1F2484 FAT flush,2AC438 directory update and original private object unlink',
            'Fresh kernel/FS context reopens persisted card model via1F43AC then1F3524 original FAT file read'],
        modeled=['110sector FAT12 partition/BPB,512bytes/sector,2sectors/cluster,4data clusters;prepared FS context/devices,not original mount',
            'PIO card updates only after original CPU store;DMA read/write hardware copies use original programmed pointers/counts and original event paths',
            'B2D50 CPU frames abstracted;callbacks/ticks entered via C ABI;synthetic status/response MMIO and modeled DSP products',
            'Heap/pool allocation/free,clock21B300/21B2CC,2A29B4,ioctl3,cache17FAA4,delay2E500C,recovery25B63C/query25BF3C remain fixtures'],
        conclusions=['New file creation,odd513byte write,dirty close,cold reopen/content and collision preservation execute original FS operations',
            'Upper status0 can accompany0 or1024-of2048written bytes because metadata cache success overwrites earlier error;fullcount can hide fileError1A00006',
            'Async timeout profile executes81original timeout returns and8100ticks across9failed engine attempts',
            'Fragmented short write leaves FAT terminalFF7 on referenced cluster;independent fsck rejects it while four positive images pass',
            'A zero status is not sufficient for dumper success;count,fileError,close anddata/metadata effects are separate'],
        limits=['Generic1F21F8 registry/12DBFC open and12D604 upper close/slots not integrated;callbacks and wrappers use prepared objects',
            'Only backend1 short names and small declared geometry;backend7,w/w+/x,concurrency,all allocation/sync errors and production adapter remain open',
            'No real DMA/electrical IRQ/cache/persistence,physical RAM map or compatible image;NON_INSTALLARE'])
    if lifecycle:
        result['status']='PASS_ORIGINAL_REGISTRY_UPPER_OPEN_CLOSE_AND_FAT_CONTROLLER_LIFECYCLE_WITH_EXPECTED_ERRORS'
        result['lifecycle']=lifecycle
        result['ownership_cases']=ownership
        result['original_bodies'] += ['2A3C5C original device registration and registry mutex/list',
            '1F21F8 generic open allocates32byte wrapper and invokes registered callback after registry unlock',
            '12DBFC n and12CE8C r/r+ upper open publish volume slot/caller cell',
            '12D604 controls3038/3015 via1F56B4 then1F22C0 original callback/free and slot/caller-cell clear']
        result['conclusions'] += ['Registry callback fields/list,count andtwo context registrations verified;generic wrapper allocation/free balancedincluding collision',
            'Upper close consumes wrapper andslot even on tested callbackE00100;preclose NULL volume control returnsFFFFFFFF andretains wrapper/private object/slot/caller untilsuccessfulretry',
            'Ready0lateclose returns1A0000C andconsumes generic wrapper/slot/caller butprivate FAT object remainslisted;notnormalcleanup',
            'Full60slot table rejects before allocation;517byte scratchOOM frees wrapper andpublishes no handle;all4ownership casespreserve110card sectors',
            'Upper3015 flush exposesFAT2=FF7 after sixzero-count write failures;only1024of2048declared file bytes remain traversable;independentfsck rejectsall7expectedbadimages']
        result['limits'][0]='Kernel registry semaphore andFS geometry prepared,registrar/open/close bodies executed;no original mount/kernel boot'
        result['limits'].append('Lifecycle suite covers13file scenarios and4ownership cases;missingvolumehandle andready0 areexplicit statefaults,notobservedhardware;upperlock/post errors remainisolatedfixtures')
    (out/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    (out.parent/'latest.json').write_text(json.dumps({'evidence':str((out/'verified_evidence.json').relative_to(ROOT))},indent=2)+'\n')
    print(trace,end='');print(out)


if __name__=='__main__':
    main()
