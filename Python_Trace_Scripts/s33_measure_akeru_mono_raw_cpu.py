#!/usr/bin/env python3
"""Count GNU ARC700 instructions for synthetic constant RGGB rasters."""
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
import json, re
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha


def main():
    out=ROOT/'Risultati/Mono_RAW'/datetime.now(timezone.utc).strftime('mono_cost_cpu_%Y%m%dT%H%M%SZ')
    r=Runner(SimpleNamespace(legacy_root=LEGACY,toolchain=TOOLCHAIN,output=out,action='mono-raw-cost'))
    print('Prove:',out,flush=True)
    try:
        r.prepare()
        src=ROOT/'AkeruOS/camera/mono_raw.c'; hdr=ROOT/'AkeruOS/camera/mono_raw.h'
        for p in (src,hdr,Path(__file__)):r.input_hashes[str(p)]=sha(p)
        def run(name,args):
            x=r.command(name,args); assert x.returncode==0,x.stdout; return x.stdout
        flags=['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-O2','-ffreestanding','-fno-builtin','-Wall','-Wextra','-Werror','-I'+str(ROOT/'AkeruOS')]
        run('compile_mono',flags+['-c',src,'-o',out/'mono.o'])
        (out/'start.s').write_text('.section .text,"ax",@progbits\n.global _start\n_start:\n mov sp,_stack_top\n bl main\n mov r8,1\n trap_s 1\n.section .stack,"aw",@nobits\n.align 16\n.space 16384\n_stack_top:\n')
        run('assemble',[TOOLCHAIN/'arc-elf32-as','-mcpu=arc700','-EL','-o',out/'start.o',out/'start.s'])
        libgcc=run('libgcc',['arc-snps-elf-gcc','-mcpu=arc700','-mno-sdata','-mlong-calls','-print-libgcc-file-name']).strip()
        rows=[]
        for n in (8,16,32,64):
            c=out/f'bench{n}.c'
            c.write_text(f'''#include "camera/mono_raw.h"
static uint16_t src[{n*n}], dst[{n*n}];
int main(void) {{ unsigned i; for (i=0;i<{n*n};i++) src[i]=1024;
 if (akeru_mono_raw(src,dst,{n},{n})!=0) return 1;
 for (i=0;i<{n*n};i++) if (dst[i]!=1219) return 2;
 return 0; }}\n''')
            run(f'compile_{n}',flags+['-c',c,'-o',out/f'bench{n}.o'])
            elf=out/f'bench{n}.elf'
            run(f'link_{n}',[TOOLCHAIN/'arc-elf32-ld','-EL','-T',LEGACY/'tests/smoke.ld','-o',elf,out/'start.o',out/f'bench{n}.o',out/'mono.o',libgcc])
            assert not run(f'undefined_{n}',['arc-snps-elf-nm','-u',elf]).strip()
            result,log=r.run(f'bench{n}','/result/'+elf.name)
            assert result['exit_code']==0 and result['fault'] is None,log
            m=re.search(r'Total instructions:\s*([\d,]+)',log); assert m,log
            ins=int(m.group(1).replace(',',''))
            rows.append(dict(width=n,height=n,pixels=n*n,total_instructions=ins,instructions_per_pixel=ins/(n*n)))
        assert all(sha(p)==r.input_hashes[str(p)] for p in (src,hdr,Path(__file__)))
        (out/'cases.json').write_text(json.dumps(rows,indent=2)+'\n')
        r.results.update(status='PASS_MONO_CPU_INSTRUCTION_COUNTS',scenarios=rows,
           assumptions=['Constant synthetic RAW 1024, expected integer output 1219; host-generated test harness initializes and checks every pixel.', 'Counts include startup, input initialization, validation, conversion and checking; GNU simulator profiler, not CPU cycles.'],
           limits=['No physical timing, cache, bus, DSP, capture, JPEG, real frame, integration or hardware. Constant data only; not a full-frame measurement.'])
        r.finish()
    except Exception as exc:
        r.results.update(status='FAIL',error=repr(exc)); raise
    finally:r.save()
    print('PASS:',rows,flush=True)
if __name__=='__main__':main()
