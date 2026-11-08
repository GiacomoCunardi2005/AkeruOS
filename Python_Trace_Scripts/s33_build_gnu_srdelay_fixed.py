#!/usr/bin/env python3
"""Fix SR's erroneous PBB branch-state reset in a separate ARC700 engine."""
from pathlib import Path
import json
import shutil
import subprocess
import difflib
from s33_run_gnu_arc700 import ROOT,LEGACY,sha,SIM_SHA

BASE=ROOT/'work/gnu_arc700_aux_fixed_v2'
PARENT=ROOT/'outputs/gnu_arc700_aux/build_v2/verified_evidence.json'
LAB=ROOT/'work/gnu_arc700_srdelay_fixed_v2'
OUT=ROOT/'outputs/gnu_arc700_srdelay/build_v2'


def main():
    assert sha(LEGACY/'install/bin/arc-elf32-run')==SIM_SHA
    parent=json.loads(PARENT.read_text());assert sha(BASE/'install/bin/arc-elf32-run')==parent['aux_fixed_sha256']
    assert not LAB.exists();LAB.mkdir(parents=True);OUT.mkdir(parents=True,exist_ok=False)
    shutil.copytree(BASE/'source',LAB/'source',symlinks=True)
    shutil.copytree(BASE/'build-gnu89',LAB/'build-gnu89',symlinks=True)
    src=LAB/'source/gnu-arc700-sim-src/sim/arc';changes={};patch=[]
    for name in ('sem7.c','sem7-switch.c','mloop7.in'):
        p=src/name;old=p.read_text();new=old
        if name=='mloop7.in':
            # Reuse the reserved, otherwise unused byte without changing layouts.
            assert new.count('  @cpu@_fill_argbuf (current_cpu, abuf, id, pc, fast_p);')==1
            new=new.replace('  @cpu@_fill_argbuf (current_cpu, abuf, id, pc, fast_p);',
                            '  @cpu@_fill_argbuf (current_cpu, abuf, id, pc, fast_p);\n  abuf->unused = 0; /* S33: default outside PBB delay slots. */')
            assert new.count('      ++sc;\n')==1
            new=new.replace('      ++sc;\n','      sc->argbuf.unused = (_cti_sc != NULL); /* S33: executed delay slot. */\n      ++sc;\n')
        else:
            start=new.index('/* sr_L_r_r' if name=='sem7.c' else '  CASE (sem, INSN_SR_L_R_R___RC_)')
            end=new.index('/* asl_L_r_r' if name=='sem7.c' else '  CASE (sem, INSN_ASL_L_R_R__RC)',start)
            part=new[start:end]
            assert part.count('  SEM_BRANCH_FINI (vpc);')==3
            # Outside a delay slot SR remains a conditional-CTI cache boundary.
            # Inside the slot it must not replace the preceding branch's state.
            part=part.replace('  SEM_BRANCH_FINI (vpc);',
                              '  if (!abuf->unused) { SEM_BRANCH_FINI (vpc); }')
            new=new[:start]+part+new[end:]
        p.write_text(new)
        changes[name]=dict(original=sha(BASE/'source/gnu-arc700-sim-src/sim/arc'/name),fixed=sha(p))
        patch.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='aux-v2/'+name,tofile='srdelay-fixed/'+name))
    (OUT/'srdelay.patch').write_text(''.join(patch));(OUT/'builder_snapshot.py').write_bytes(Path(__file__).read_bytes())
    (OUT/'parent_aux_build.json').write_bytes(PARENT.read_bytes())
    cmd=['podman','run','--rm','--network','none','--memory','2g','--volume',f'{LAB}:/work:rw',
         '--workdir','/work/build-gnu89/sim/arc','localhost/arc700-legacy:gcc10','make','-j2','CFLAGS='+parent['instrumentation'],'run']
    (OUT/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    with (OUT/'build.log').open('w') as stream:p=subprocess.run(cmd,stdout=stream,stderr=subprocess.STDOUT,timeout=300)
    assert p.returncode==0,(OUT/'build.log').read_text()[-2500:]
    binary=LAB/'install/bin/arc-elf32-run';binary.parent.mkdir(parents=True)
    shutil.copyfile(LAB/'build-gnu89/sim/arc/run',binary);binary.chmod(0o755)
    assert sha(LEGACY/'install/bin/arc-elf32-run')==SIM_SHA
    result=dict(parent);result.update(status='BUILD_ONLY',binary=str(binary),aux_fixed_sha256=sha(binary),
       parent_aux_fixed_sha256=parent['aux_fixed_sha256'],sr_delay_branch_preserved=True,changes=changes,
       limits=parent['limits']+['SR opcode branch-state fix needs isolated tests and firmware comparison',
          'No new hardware/IRQ delivery or DSP semantics added',
          'Reserved ARGBUF unused byte marks a parsed delay slot; SR reset retained outside it'])
    (OUT/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    print(binary,sha(binary),flush=True)


if __name__=='__main__':main()
