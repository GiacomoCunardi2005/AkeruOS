#!/usr/bin/env python3
"""Fix the shared GNU AUX storage boundary in a separate, bounds-instrumented engine."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import difflib

ROOT=Path(__file__).resolve().parents[1]
BASE=Path('/home/jack/opt/arc700-legacy')
LAB=ROOT/'work/gnu_arc700_aux_fixed_v2'
OUT=ROOT/'outputs/gnu_arc700_aux/build_v2'
PIN='7d6ccd1bc2291f377201e8cd1027c6ecf94d30901f13251c1c6bf647aa8a43dc'
FLAGS='-O2 -g -std=gnu11 -fgnu89-inline -fcommon -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=700 -fsanitize=bounds -fno-sanitize-recover=all'

READ=r'''#define S33_AUX_READ(index) \
({ UINT s33_i = (UINT) (index); SI s33_value = 0; \
  if (s33_i >= 2048) { \
    sim_io_eprintf (CPU_STATE (current_cpu), "S33_AUX_RANGE index=%u\n", s33_i); \
    cgen_rtx_error (current_cpu, "AUX index outside configured 0..2047 bank"); \
  } else if (s33_i >= 64 && !CPU (h_s33_aux_valid[s33_i]) && s33_i != 0x94) { \
    sim_io_eprintf (CPU_STATE (current_cpu), "S33_AUX_UNKNOWN index=%u\n", s33_i); \
    cgen_rtx_error (current_cpu, "Unconfigured extended AUX read"); \
  } else { \
    s33_value = CPU (h_auxr[s33_i]); \
    if (s33_i >= 64 && !CPU (h_s33_aux_valid[s33_i])) { \
      CPU (h_s33_aux_valid[s33_i]) = 1; \
      sim_io_eprintf (CPU_STATE (current_cpu), "S33_AUX_LAB_RESET index=%u value=00000000 assumed=1\n", s33_i); \
    } \
  } \
  s33_value; })
'''
WRITE=r'''  default : {\
UINT s33_i = (UINT) (index);\
if (s33_i >= 2048) {\
sim_io_eprintf (CPU_STATE (current_cpu), "S33_AUX_RANGE index=%u\n", s33_i);\
cgen_rtx_error (current_cpu, "AUX index outside configured 0..2047 bank");\
} else {\
CPU (h_auxr[s33_i]) = (x);\
CPU (h_s33_aux_valid[s33_i]) = 1;\
if (s33_i >= 64) sim_io_eprintf (CPU_STATE (current_cpu), "S33_AUX_LAB_WRITE index=%u value=%08x storage_only=1\n", s33_i, (USI) (x));\
}\
}\
'''


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def once(text,old,new):
    assert text.count(old)==1,old[:60]
    return text.replace(old,new)


def main():
    assert sha(BASE/'install/bin/arc-elf32-run')==PIN
    assert not LAB.exists()
    LAB.mkdir(parents=True);OUT.mkdir(parents=True,exist_ok=False)
    shutil.copytree(BASE/'source',LAB/'source',symlinks=True)
    shutil.copytree(BASE/'build-gnu89',LAB/'build-gnu89',symlinks=True)
    sources=LAB/'source/gnu-arc700-sim-src/sim/arc';patches=[];hashes={}
    for name in ('cpu5.h','cpu6.h','cpu7.h'):
        p=sources/name;old=p.read_text()
        read=READ
        if name=='cpu7.h':
            # ARC International 5115-029 p54 and table22 pp75-76:
            # ARC700 IRQ3..31 reset to priority level1 (bits zero).
            read=once(read,'&& s33_i != 0x94)',
                      '&& s33_i != 0x94 && s33_i != 0x43 && s33_i != 0x200)')
            read=once(read,'      sim_io_eprintf (CPU_STATE (current_cpu), "S33_AUX_LAB_RESET index=%u value=00000000 assumed=1\\n", s33_i); \\\n',
                      '      if (s33_i == 0x43 || s33_i == 0x200) sim_io_eprintf (CPU_STATE (current_cpu), "S33_AUX_ARCH_RESET index=%u value=00000000\\n", s33_i); \\\n'
                      '      else sim_io_eprintf (CPU_STATE (current_cpu), "S33_AUX_LAB_RESET index=%u value=00000000 assumed=1\\n", s33_i); \\\n')
        new=once(old,'  SI h_auxr[64];','  SI h_auxr[2048];\n'+read)
        new=once(new,'(CPU (h_auxr[index]))','S33_AUX_READ (index)')
        new=once(new,'  } hardware;','  UQI h_s33_aux_valid[2048];\n  } hardware;')
        new=once(new,'  default : {\\\nCPU (h_auxr[(index)]) = (x);\\\n}\\\n',WRITE)
        new=once(new,'  case 65 : {\\\n',
                 '  case 65 : {\\\nCPU (h_auxr[65]) = (x);\\\nCPU (h_s33_aux_valid[65]) = 1;\\\n')
        if name=='cpu7.h':
            irq=r'''  case 67 : {\
CPU (h_auxr[67]) &= ~((USI) (x) & 3);\
CPU (h_auxr[67]) &= 3;\
CPU (h_s33_aux_valid[67]) = 1;\
sim_io_eprintf (CPU_STATE (current_cpu), "S33_IRQ_W1C value=%08x status=%08x\n", (USI) (x), (USI) CPU (h_auxr[67]));\
}\
    break;\
  case 512 : {\
CPU (h_auxr[512]) = (USI) (x) & 0xfffffff8;\
CPU (h_s33_aux_valid[512]) = 1;\
sim_io_eprintf (CPU_STATE (current_cpu), "S33_IRQ_PRIORITY value=%08x\n", (USI) CPU (h_auxr[512]));\
}\
    break;\
'''
            new=once(new,'  default : {\\\nUINT s33_i',irq+'  default : {\\\nUINT s33_i')
        p.write_text(new)
        patches.append(''.join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),
                         fromfile='original/'+name,tofile='aux-fixed/'+name)))
        hashes[name]=dict(original=hashlib.sha256(old.encode()).hexdigest(),fixed=sha(p))
    (OUT/'aux_bounds.patch').write_text(''.join(patches))
    (OUT/'builder_snapshot.py').write_bytes(Path(__file__).read_bytes())
    # All CPU families and their common ARC5 register-access helpers share the
    # layout. Recompile the simulator subsystem together after changing it.
    cmd=['podman','run','--rm','--network','none','--memory','2g','--volume',f'{LAB}:/work:rw',
         '--workdir','/work/build-gnu89/sim/arc','localhost/arc700-legacy:gcc10',
         'sh','-c','make clean && make -j2 '+"CFLAGS='"+FLAGS+"' run"]
    (OUT/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    with (OUT/'build.log').open('w') as f:p=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,timeout=300)
    assert p.returncode==0,(OUT/'build.log').read_text()[-2500:]
    binary=LAB/'install/bin/arc-elf32-run';binary.parent.mkdir(parents=True)
    shutil.copyfile(LAB/'build-gnu89/sim/arc/run',binary);binary.chmod(0o755)
    assert sha(BASE/'install/bin/arc-elf32-run')==PIN
    (OUT/'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY',binary=str(binary),
        original_sha256=PIN,aux_fixed_sha256=sha(binary),headers=hashes,instrumentation=FLAGS,
        dsp_extensions_added=False,aux_capacity=2048,
        documented_irq_registers=['0x43 W1C status, initially no IRQ taken','0x200 priorities IRQ3..31, reserved bits0..2 zero'],
        irq_reference='ARC International 5115-029 figure51 p54 and table22 pp75-76',
        assumptions=['AUX94 vector base reset0 laboratory assumption retained explicitly',
                     'Extended AUX writes are storage only; physical device effects not modeled'],
        limits=['Unknown extended AUX reads stop','No DSP semantics added','MACMODE special semantics otherwise retained',
                'Interrupt generation/delivery beyond the pre-existing GNU timer model not implemented']),indent=2)+'\n')
    print(binary,sha(binary),flush=True)


if __name__=='__main__':main()
