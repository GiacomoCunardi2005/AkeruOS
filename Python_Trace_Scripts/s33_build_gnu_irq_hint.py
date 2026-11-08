#!/usr/bin/env python3
"""Model an explicitly empty software-IRQ source; stop on any unsupported request."""
from pathlib import Path
import json,shutil,subprocess,difflib
from s33_run_gnu_arc700 import ROOT,LEGACY,sha,SIM_SHA

BASE=ROOT/'work/gnu_arc700_srdelay_fixed_v2'
PARENT=ROOT/'outputs/gnu_arc700_srdelay/build_v2/verified_evidence.json'
LAB=ROOT/'work/gnu_arc700_irq_hint_v1'
OUT=ROOT/'outputs/gnu_arc700_irq_hint/build_v1'


def once(text,old,new):
    assert text.count(old)==1,old[:80]
    return text.replace(old,new)


def main():
    assert sha(LEGACY/'install/bin/arc-elf32-run')==SIM_SHA
    parent=json.loads(PARENT.read_text());assert sha(BASE/'install/bin/arc-elf32-run')==parent['aux_fixed_sha256']
    assert not LAB.exists();LAB.mkdir(parents=True);OUT.mkdir(parents=True,exist_ok=False)
    shutil.copytree(BASE/'source',LAB/'source',symlinks=True)
    shutil.copytree(BASE/'build-gnu89',LAB/'build-gnu89',symlinks=True)
    p=LAB/'source/gnu-arc700-sim-src/sim/arc/cpu7.h';old=p.read_text()
    marker='  } else if (s33_i >= 64 && !CPU (h_s33_aux_valid[s33_i])'
    empty=r'''  } else if (s33_i == 0x201) { \
    /* This variant has no injected host IRQs and no supported nonzero SR requests. \
       An empty software source is simulator state, NOT a Nikon reset reading. */ \
    if (!CPU (h_s33_aux_valid[513])) { \
      CPU (h_auxr[513]) = 0; CPU (h_s33_aux_valid[513]) = 1; \
      sim_io_eprintf (CPU_STATE (current_cpu), "S33_IRQ_HINT_EMPTY host_requests=0 guest_requests=0 laboratory_state=1\n"); \
    } \
    s33_value = CPU (h_auxr[513]); \
'''
    new=once(old,marker,empty+marker)
    case=r'''  case 513 : {\
USI s33_request = (USI) (x);\
if (s33_request != 0) {\
sim_io_eprintf (CPU_STATE (current_cpu), "S33_IRQ_HINT_UNSUPPORTED request=%08x delivery_not_implemented=1\n", s33_request);\
cgen_rtx_error (current_cpu, "Nonzero software IRQ request requires delivery model");\
} else {\
CPU (h_auxr[513]) = 0; CPU (h_s33_aux_valid[513]) = 1;\
sim_io_eprintf (CPU_STATE (current_cpu), "S33_IRQ_HINT_CLEAR value=00000000\n");\
}\
}\
    break;\
'''
    new=once(new,'  default : {\\\nUINT s33_i',case+'  default : {\\\nUINT s33_i');p.write_text(new)
    (OUT/'irq_hint.patch').write_text(''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='srdelay-v2/cpu7.h',tofile='irq-hint-lab/cpu7.h')))
    (OUT/'builder_snapshot.py').write_bytes(Path(__file__).read_bytes());(OUT/'parent_build.json').write_bytes(PARENT.read_bytes())
    cmd=['podman','run','--rm','--network','none','--memory','2g','--volume',f'{LAB}:/work:rw',
         '--workdir','/work/build-gnu89/sim/arc','localhost/arc700-legacy:gcc10','make','-j2','CFLAGS='+parent['instrumentation'],'run']
    (OUT/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    with (OUT/'build.log').open('w') as f:proc=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
    assert proc.returncode==0,(OUT/'build.log').read_text()[-2500:]
    binary=LAB/'install/bin/arc-elf32-run';binary.parent.mkdir(parents=True)
    shutil.copyfile(LAB/'build-gnu89/sim/arc/run',binary);binary.chmod(0o755)
    headers=dict(parent['headers']);headers['cpu7.h']=dict(parent['headers']['cpu7.h'],fixed=sha(p))
    result=dict(parent);result.update(status='BUILD_ONLY',binary=str(binary),aux_fixed_sha256=sha(binary),headers=headers,
        parent_srdelay_sha256=parent['aux_fixed_sha256'],irq_hint_empty_lab=True,
        changes={'cpu7.h':dict(parent=sha(BASE/'source/gnu-arc700-sim-src/sim/arc/cpu7.h'),lab=sha(p))},
        limits=parent['limits']+['AUX201 empty software-source state only, not a physical reset value',
          'SR0 clears; every nonzero request stops instead of pretending delivery',
          'Pre-existing GNU timer interrupt source remains independent and unvalidated against Nikon'])
    (OUT/'verified_evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    assert sha(LEGACY/'install/bin/arc-elf32-run')==SIM_SHA
    print(binary,sha(binary),flush=True)


if __name__=='__main__':main()
