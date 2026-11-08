#!/usr/bin/env python3
"""Build a separate, explicitly provisional ARC700 DSP experiment; never patch Nikon bytes."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import difflib

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = Path('/home/jack/opt/arc700-legacy')
BASE = ROOT/'work/gnu_arc700_irq_hint_v1'
PARENT = ROOT/'outputs/gnu_arc700_irq_hint/build_v1/verified_evidence.json'
LAB = ROOT/'work/gnu_arc700_dsp_lab_v7'
OUT = ROOT/'outputs/gnu_arc700_dsp/build_v7'
PIN = '7d6ccd1bc2291f377201e8cd1027c6ecf94d30901f13251c1c6bf647aa8a43dc'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def replace_once(text, old, new):
    assert text.count(old) == 1, old[:100]
    return text.replace(old, new)


GUARD = r'''
/* S33 experimental DSP subset, NOT a complete or hardware-validated DSP model.
   Original instruction bytes are unchanged. The generic 4-byte R/R descriptor
   is an internal carrier only; S33_DSP_LAB records identify the real operation.
   Sources: MAME dual signed product plus Nikon's raw-r57 consumer (inference).
   Only ZA, no .f, ordinary registers, explicit MACMODE=0.
   Signed: low positive lanes or zero operand, as in v3.
   Unsigned: raw lane products, each <= 0x7fffffff (exclude possible saturation).
   Raw lane ordering and unused DSP side effects remain an explicit inference.
 */
{
  USI s33_word = ((USI) GETMEMUHI (current_cpu, pc, pc) << 16)
    | GETMEMUHI (current_cpu, pc, pc + 2);
  USI s33_kind = s33_word & 0xf8ff803f;
  if (s33_kind == 0x280c003e || s33_kind == 0x280d003e)
    {
      USI s33_left = GET_H_CR (FLD (f_op_B));
      USI s33_right = GET_H_CR (FLD (f_op_C));
      USI s33_high = (s33_left >> 16) * (s33_right >> 16);
      USI s33_low = (s33_left & 65535) * (s33_right & 65535);
      int s33_domain = s33_kind == 0x280d003e
        ? (s33_high <= 0x7fffffff && s33_low <= 0x7fffffff)
        : ((s33_left <= 0x7fff && s33_right <= 0x7fff) || s33_left == 0 || s33_right == 0);
      if (!CPU (h_s33_aux_valid[65]) || CPU (h_auxr[65]) != 0 || !s33_domain)
        {
          sim_io_eprintf (CPU_STATE (current_cpu),
            "S33_DSP_GUARD pc=%08x word=%08x left=%08x right=%08x mode=%08x seen=%u\n",
            pc, s33_word, s33_left, s33_right,
            (USI) CPU (h_auxr[65]), CPU (h_s33_aux_valid[65]));
          cgen_rtx_error (current_cpu, "S33 DSP experiment: unsupported state");
        }
      SET_H_CR (56, s33_high);
      SET_H_CR (57, s33_low);
      sim_io_eprintf (CPU_STATE (current_cpu),
        "S33_DSP_LAB pc=%08x word=%08x left=%08x right=%08x r56=%08x r57=%08x provisional=1\n",
        pc, s33_word, s33_left, s33_right, s33_high, s33_low);
      goto s33_lab_done;
    }
}
'''


def main():
    original = ORIGINAL/'install/bin/arc-elf32-run'
    assert sha(original) == PIN
    parent = json.loads(PARENT.read_text())
    assert sha(BASE/'install/bin/arc-elf32-run') == parent['aux_fixed_sha256']
    OUT.mkdir(parents=True, exist_ok=True)
    assert not LAB.exists(), 'Existing lab preserved; review it before rebuilding in another directory'
    # Preserve absolute /work paths in the original build by mounting this clone there.
    LAB.mkdir(parents=True)
    shutil.copytree(BASE/'source', LAB/'source', symlinks=True)
    shutil.copytree(BASE/'build-gnu89', LAB/'build-gnu89', symlinks=True)
    src = LAB/'source/gnu-arc700-sim-src/sim/arc'
    changed = {}
    for name in ('cpu5.h','cpu6.h','cpu7.h'):
        assert sha(src/name) == parent['headers'][name]['fixed']
    p = src/'decode7.c'; old = p.read_text()
    marker = '    CGEN_INSN_INT insn = base_insn;'
    decode = r'''
    /* Deliberately restricted provisional S33 DSP subset, not a replacement ISA. */
    {
      USI kind = entire_insn & 0xf8ff803f;
      USI b = ((entire_insn >> 24) & 7) | (((entire_insn >> 12) & 7) << 3);
      USI c = (entire_insn >> 6) & 63;
      if ((kind == 0x280c003e || kind == 0x280d003e) && b < 32 && c < 32)
        {
          itype = ARC700F_INSN_MULULW_L_R_R__RA__RC;
          goto extract_sfmt_add_L_r_r__RA__RC;
        }
    }
'''
    new = replace_once(old, marker, marker+'\n'+decode)
    p.write_text(new); changed[p.name] = (old,new)
    for name in ('sem7.c','sem7-switch.c'):
        p = src/name; old = p.read_text()
        start_marker = '/* mululw_L_r_r $RA,$RC:' if name == 'sem7.c' else '  CASE (sem, INSN_MULULW_L_R_R__RA__RC)'
        end_marker = '/* mululw_cc $RA,$RC:' if name == 'sem7.c' else '  CASE (sem, INSN_MULULW_CC__RA__RC)'
        start = old.index(start_marker)
        end = old.index(end_marker,start)
        part = old[start:end]
        marker = ('  SEM_PC vpc = SEM_NEXT_VPC (sem_arg, pc, 4);' if name == 'sem7.c'
                  else '  vpc = SEM_NEXT_VPC (sem_arg, pc, 4);')
        assert marker in part
        part = replace_once(part, marker, marker+'\n'+GUARD)
        part = replace_once(part, '  abuf->written = written;', 's33_lab_done:\n  abuf->written = written;')
        new = old[:start]+part+old[end:]
        p.write_text(new); changed[p.name] = (old,new)
    patch = ''.join(''.join(difflib.unified_diff(a.splitlines(True),b.splitlines(True),
                         fromfile='original/'+name,tofile='lab/'+name)) for name,(a,b) in changed.items())
    (OUT/'dsp_subset.patch').write_text(patch)
    (OUT/'builder_snapshot.py').write_bytes(Path(__file__).read_bytes())
    (OUT/'parent_aux_build.json').write_bytes(PARENT.read_bytes())
    cmd = ['podman','run','--rm','--network','none','--memory','2g',
           '--volume',f'{LAB}:/work:rw','--workdir','/work/build-gnu89/sim/arc',
           'localhost/arc700-legacy:gcc10','make','-j2','CFLAGS='+parent['instrumentation'],'run']
    (OUT/'command.json').write_text(json.dumps(cmd,indent=2)+'\n')
    with (OUT/'build.log').open('w') as stream:
        p = subprocess.run(cmd, stdout=stream,stderr=subprocess.STDOUT,timeout=300)
    assert p.returncode == 0, (OUT/'build.log').read_text()[-3000:]
    dest = LAB/'install/bin/arc-elf32-run'; dest.parent.mkdir(parents=True)
    shutil.copyfile(LAB/'build-gnu89/sim/arc/run',dest);dest.chmod(0o755)
    assert sha(original) == PIN
    (OUT/'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY',
        original_sha256=PIN,parent_aux_fixed_sha256=parent['aux_fixed_sha256'],
        aux_bounds_fixed=True,instrumentation=parent['instrumentation'],
        experimental_sha256=sha(dest),binary=str(dest),
        changed={name:dict(original=hashlib.sha256(a.encode()).hexdigest(),lab=hashlib.sha256(b.encode()).hexdigest()) for name,(a,b) in changed.items()},
        model='Provisional ZA/noF register-register DSP; unsigned non-saturating lane products; signed low-positive/zero',
        independent_complete_semantics_proven=False,
        assumptions=['r56=upper-lane product,r57=lower-lane product inferred from Nikon consumer',
                     'No other DSP effects in positive non-saturating MACMODE0 subset'],
        limits=['Not complete ISA','Not a physical CPU result','Execution/result tests required']),indent=2)+'\n')
    print(dest,sha(dest),flush=True)


if __name__ == '__main__':
    main()
