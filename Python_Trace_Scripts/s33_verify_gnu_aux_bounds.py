#!/usr/bin/env python3
"""Instrument a separate copy of the original engine to check the AUX array boundary."""
from pathlib import Path
from types import SimpleNamespace
import json
import shutil
import subprocess
from s33_run_gnu_arc700 import ROOT,LEGACY,TOOLCHAIN,Runner,sha
from s33_verify_gnu_dsp_lab import compile_probe

LAB=ROOT/'work/gnu_arc700_aux_bounds_v2'
FLAGS='-O2 -g -std=gnu11 -fgnu89-inline -fcommon -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=700 -fsanitize=bounds -fno-sanitize-recover=all'


def main():
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=None,action='original-aux-bounds-diagnostic'))
    print('Evidence:',r.out,flush=True)
    try:
        r.prepare();assert not LAB.exists()
        (r.out/'bounds_verifier_snapshot.py').write_bytes(Path(__file__).read_bytes())
        LAB.mkdir(parents=True)
        shutil.copytree(LEGACY/'source',LAB/'source',symlinks=True)
        shutil.copytree(LEGACY/'build-gnu89',LAB/'build-gnu89',symlinks=True)
        # Flags alone are not make prerequisites. Force the two semantic units
        # (function and switch paths) and the final archive/link to be rebuilt.
        for name in ('sem7.o','mloop7.o','libsim.a','run'):
            (LAB/'build-gnu89/sim/arc'/name).unlink()
        cmd=['podman','run','--rm','--network','none','--memory','2g','--volume',f'{LAB}:/work:rw',
             '--workdir','/work/build-gnu89/sim/arc','localhost/arc700-legacy:gcc10',
             'make','-j2','CFLAGS='+FLAGS,'run']
        (r.out/'instrument.command.json').write_text(json.dumps(cmd,indent=2)+'\n')
        with (r.out/'instrument.log').open('w') as out:
            p=subprocess.run(cmd,stdout=out,stderr=subprocess.STDOUT,timeout=300)
        assert p.returncode==0,(r.out/'instrument.log').read_text()[-2000:]
        dest=LAB/'install/bin/arc-elf32-run';dest.parent.mkdir(parents=True)
        shutil.copyfile(LAB/'build-gnu89/sim/arc/run',dest);dest.chmod(0o755)
        r.experimental_engine=LAB
        results=[]
        for name,asm,expected in [('aux94_read',' lr r0,[0x94]\n',148),
                                  ('aux45_write',' sr 0,[0x45]\n',69)]:
            elf=compile_probe(r,name,asm+' mov r0,0\n mov r8,1\n trap_s 1\n')
            cmd=['podman','run','--rm','--network','none','--memory','2g',
                 '--volume',f'{LAB}:/engine:ro','--volume',f'{r.out}:/result:ro',
                 'localhost/arc700-legacy:gcc10','timeout','10s',
                 '/engine/install/bin/arc-elf32-run','-v',f'/result/{elf.name}']
            p=r.command(name,cmd)
            assert p.returncode!=0 and p.returncode not in (124,125,126,127)
            assert f'index {expected} out of bounds' in p.stdout,p.stdout
            results.append(dict(name=name,aux_index=expected,exit_code=p.returncode,ubsan_confirmed=True))
            print('CONFIRMED',name,expected,flush=True)
        r.results.update(status='CONFIRMED_MODEL_DEFECT',instrumented_sha256=sha(dest),
                         source_modified=False,instrumentation=FLAGS,aux_bounds=results,
                         physical_cpu_fault_proven=False)
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc));raise
    finally:r.save()
    print(r.results['status'],r.out/'verified_evidence.json',flush=True)


if __name__=='__main__':main()
