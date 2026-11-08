#!/usr/bin/env python3
"""Build a separate GNU DSPv7 engine with per-byte RAM provenance checks."""
from pathlib import Path
import difflib
import json
import shutil
import subprocess
from s33_run_gnu_arc700 import ROOT, LEGACY, SIM_SHA, sha

BASE=ROOT/'work/gnu_arc700_dsp_lab_v7'
PARENT=ROOT/'outputs/gnu_arc700_dsp/build_v7/verified_evidence.json'
LAB=ROOT/'work/gnu_arc700_defined_memory_v2'
OUT=ROOT/'outputs/gnu_arc700_defined_memory/build_v2'
TRACKER=ROOT/'S33-sections/analysis_codex/s33_gnu_defined_memory.c'


def main():
    assert sha(LEGACY/'install/bin/arc-elf32-run')==SIM_SHA
    parent=json.loads(PARENT.read_text());assert sha(BASE/'install/bin/arc-elf32-run')==parent['experimental_sha256']
    assert not LAB.exists() and not OUT.exists(), 'Existing experiments preserved'
    LAB.mkdir(parents=True);OUT.mkdir(parents=True)
    shutil.copytree(BASE/'source',LAB/'source',symlinks=True)
    shutil.copytree(BASE/'build-gnu89',LAB/'build-gnu89',symlinks=True)
    source=LAB/'source/gnu-arc700-sim-src/sim';changes={};patch=[]
    for rel in ('arc/sim-main.h','arc/sim-if.c','common/cgen-mem.h'):
        p=source/rel;old=p.read_text();new=old
        if rel=='arc/sim-main.h':
            marker='#endif /* SIM_MAIN_H */';assert new.count(marker)==1
            new=new.replace(marker,'extern void s33_require_defined (SIM_CPU *, IADDR, ADDR, unsigned, int);\n'
                'extern void s33_store_defined (SIM_CPU *, IADDR, ADDR, unsigned);\n'+marker)
        elif rel=='arc/sim-if.c':
            marker='static void free_state (SIM_DESC);';assert new.count(marker)==1
            new=new.replace(marker,TRACKER.read_text()+'\n'+marker)
            start=new.index('SIM_RC\nsim_create_inferior');end=new.index('/* PROFILE_CPU_CALLBACK */',start)
            section=new[start:end];assert section.count('  return SIM_RC_OK;')==1
            section=section.replace('  return SIM_RC_OK;','  s33_defined_active = 1; /* Host setup is not guest execution. */\n  return SIM_RC_OK;')
            new=new[:start]+section+new[end:]
        else:
            read='  PROFILE_COUNT_READ (cpu, a, XCONCAT2 (MODE_,mode)); \\\n'
            assert new.count(read)==2
            new=new.replace(read,'  s33_require_defined (cpu, pc, a, size, 0); \\\n'+read)
            write='  XCONCAT2 (sim_core_write_unaligned_,size) (cpu, pc, write_map, a, val); \\\n'
            assert new.count(write)==2
            new=new.replace(write,write+'  s33_store_defined (cpu, pc, a, size); \\\n')
            fetch='  return XCONCAT2 (sim_core_read_unaligned_,size) (cpu, a, exec_map, a); \\\n'
            assert new.count(fetch)==1
            new=new.replace(fetch,'  s33_require_defined (cpu, a, a, size, 1); \\\n'+fetch)
        p.write_text(new);changes[rel]=dict(parent=sha(BASE/'source/gnu-arc700-sim-src/sim'/rel),lab=sha(p))
        patch.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='DSPv7/'+rel,tofile='defined-memory/'+rel))
    (OUT/'defined_memory.patch').write_text(''.join(patch));(OUT/'builder_snapshot.py').write_bytes(Path(__file__).read_bytes())
    (OUT/'tracker_snapshot.c').write_bytes(TRACKER.read_bytes());(OUT/'parent_build.json').write_bytes(PARENT.read_bytes())
    cmd=['podman','run','--rm','--network','none','--memory','2g','--volume',f'{LAB}:/work:rw',
        '--workdir','/work/build-gnu89/sim/arc','localhost/arc700-legacy:gcc10','make','-j2','CFLAGS='+parent['instrumentation'],'run']
    (OUT/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    with (OUT/'build.log').open('w') as f:p=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
    assert p.returncode==0,(OUT/'build.log').read_text()[-6000:]
    binary=LAB/'install/bin/arc-elf32-run';binary.parent.mkdir(parents=True);shutil.copyfile(LAB/'build-gnu89/sim/arc/run',binary);binary.chmod(0o755)
    assert sha(LEGACY/'install/bin/arc-elf32-run')==SIM_SHA
    assert sha(BASE/'install/bin/arc-elf32-run')==parent['experimental_sha256']
    (OUT/'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY',engine_sha256=sha(binary),parent_engine_sha256=parent['experimental_sha256'],
        instrumentation=parent['instrumentation'],changes=changes,tracker_sha256=sha(TRACKER),bank_bytes=128*1024*1024,
        limits=['Single CPU/process; initial known ranges explicitly declared by harness','MMIO and CPU/AUX registers outside RAM tracking',
                'Decoder fetch includes parser lookahead, not only retired instructions','DSPv7 remains provisional; no complete boot']),indent=2)+'\n')
    print(binary,sha(binary),flush=True)


if __name__=='__main__':main()
