#!/usr/bin/env python3
"""Test proposed Nikon RAW wrapper natively and on ARC, with recording bindings."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha


def main():
    out=ROOT/'Risultati/USB_SCSI/Accesso_NAND_PC'/datetime.now(timezone.utc).strftime('raw_adapter_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='Nikon-raw-adapter-offline'))
    r.prepare()
    try:
        src=ROOT/'S33-sections/usb_nand_readonly'
        files=[src/'nikon_raw_read.c',src/'nikon_raw_read.h',src/'test_nikon_raw_read.c',src/'akrn_read.h']
        r.input_hashes.update({str(p):sha(p)for p in files})
        common=['-std=c99','-Wall','-Wextra','-Werror','-Wconversion','-pedantic']
        p=r.command('native_build',['cc',*common,'-fsanitize=address,undefined','-g',src/'nikon_raw_read.c',src/'test_nikon_raw_read.c','-o',out/'native_test']);assert p.returncode==0,p.stdout
        p=r.command('native_test',[out/'native_test']);assert p.returncode==0 and 'PASS:'in p.stdout,p.stdout
        objects=[]
        cc=TOOLCHAIN/'arc-elf32-gcc';r.input_hashes[str(cc)]=sha(cc)
        for source in [src/'nikon_raw_read.c',src/'test_nikon_raw_read.c']:
            obj=out/(source.stem+'.o');objects.append(obj)
            p=r.command(source.stem+'_compile',[cc,*common,'-DARC_TEST','-mcpu=arc700','-mlittle-endian','-mno-sdata','-ffreestanding','-fno-builtin','-Os','-c',source,'-o',obj]);assert p.returncode==0,p.stdout
        (out/'entry.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n bl main\n mov r8,1\n trap_s 1\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n')
        p=r.command('entry_assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'entry.o',out/'entry.s']);assert p.returncode==0,p.stdout
        p=r.command('arc_link',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',out/'test.elf',out/'entry.o',*objects]);assert p.returncode==0,p.stdout
        p=r.command('arc_disassembly',[TOOLCHAIN/'arc-elf32-objdump','-dr',out/'test.elf']);assert p.returncode==0,p.stdout
        case,log=r.run('arc_adapter_test','/result/test.elf',trace=True)
        assert case['exit_code']==0 and case['fault']is None,log
        assert all(sha(Path(p))==h for p,h in r.input_hashes.items())
        for p in files:(out/p.name).write_bytes(p.read_bytes())
        (out/'verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        r.results.update(status='PASS_NATIVE_AND_ARC_RAW_ADAPTER',tool_inputs=r.input_hashes,assumptions=['Geometry and service return values are explicit fixtures','All five Nikon symbol bindings are recorders; no physical reader executed'],limits=['No hardware, USB or installable update','Confirmed physical block count must be provided from independent evidence; zero refuses all raw access','Row count at most65536 and extra address cycle flag rejected; not a universal NAND implementation'])
        (out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n')
        (out.parent/'raw_adapter_latest.json').write_text(json.dumps(dict(evidence=str((out/'verified_evidence.json').relative_to(ROOT))),indent=2)+'\n')
        print('PASS',out)
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));(out/'verified_evidence.json').write_text(json.dumps(r.results,indent=2)+'\n');raise
if __name__=='__main__':main()
