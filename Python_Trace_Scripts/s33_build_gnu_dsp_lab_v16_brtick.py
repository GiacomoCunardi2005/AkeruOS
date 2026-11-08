#!/usr/bin/env python3
"""Variante di laboratorio v16: parte dalla v15 e corregge il punto d'aggancio. Il motore gira in modalita' pseudo-basic-block (-pbb), dove `vpc` e'
un puntatore alla cache e non un indirizzo, quindi i confronti di v14/v15 non scattano mai. Qui si intercetta il salto: se l'istruzione appena
eseguita ha impostato una destinazione CPU_PBB_BR_NPC = 0xB2D50 (ingresso dello scheduler), la destinazione viene sostituita con lo stub del probe
(S33_SCHEDVEC=<stub>,<flag>) e marcata non cacheabile; il rientro dallo stub (flag=1) non viene dirottato. Modella un tick TIMER0 a ogni cambio di
contesto. Limite noto: due salti consecutivi identici verso 0xB2D50 senza altri salti in mezzo producono un solo tick. Non cambia i byte Nikon."""
from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v15_schedtick'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v15_schedtick/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v16_brtick'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v16_brtick'
OLD = '''    if (s33_st && (USI) vpc == 0xb2d50) {  /* ingresso nello scheduler: interrupt TIMER0 modellato */
      if (GETMEMSI (current_cpu, 0, s33_sf)) SETMEMSI (current_cpu, 0, s33_sf, 0);
      else vpc = s33_st;
    }
'''
OLD2 = 'execute (SIM_CPU *current_cpu, SCACHE *sc, int fast_p)\n{\n  SEM_PC vpc;\n'
NEW2 = OLD2 + '  IADDR s33_pnpc = CPU_PBB_BR_NPC (current_cpu); int s33_ptype = CPU_PBB_BR_TYPE (current_cpu);\n'
NEW = '''    if (s33_st && CPU_PBB_BR_TYPE (current_cpu) != SEM_BRANCH_UNTAKEN && CPU_PBB_BR_NPC (current_cpu) == 0xb2d50
        && (CPU_PBB_BR_NPC (current_cpu) != s33_pnpc || (int) CPU_PBB_BR_TYPE (current_cpu) != s33_ptype)) {
      /* salto appena impostato verso lo scheduler: interrupt TIMER0 modellato */
      if (GETMEMSI (current_cpu, 0, s33_sf)) SETMEMSI (current_cpu, 0, s33_sf, 0);
      else { CPU_PBB_BR_NPC (current_cpu) = s33_st; CPU_PBB_BR_TYPE (current_cpu) = SEM_BRANCH_UNCACHEABLE; }
    }
'''


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    assert not LAB.exists(), 'variante v16 gia presente'
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.copytree(BASE, LAB, symlinks=True)
    for rel in ('source/gnu-arc700-sim-src/sim/arc/mloop7.in', 'build-gnu89/sim/arc/mloop7.c'):
        p = LAB / rel
        t = p.read_text()
        assert t.count(OLD) == 1 and t.count(OLD2) == 1, (rel, t.count(OLD), t.count(OLD2))
        p.write_text(t.replace(OLD, NEW).replace(OLD2, NEW2))
    (LAB / 'build-gnu89/sim/arc/mloop7.o').unlink()
    cmd = ['podman', 'run', '--rm', '--network', 'none', '--memory', '2g', '--volume', f'{LAB}:/work:rw', '--workdir', '/work/build-gnu89/sim/arc',
           'localhost/arc700-legacy:gcc10', 'make', '-j2', 'CFLAGS=' + parent['instrumentation'], 'run']
    (OUT / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
    with (OUT / 'build.log').open('w') as stream:
        p = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, timeout=1500)
    assert p.returncode == 0, (OUT / 'build.log').read_text()[-3000:]
    dest = LAB / 'install/bin/arc-elf32-run'
    shutil.copyfile(LAB / 'build-gnu89/sim/arc/run', dest)
    dest.chmod(0o755)
    (OUT / 'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY', parent_v15_sha256=parent['experimental_sha256'], experimental_sha256=sha(dest),
        binary=str(dest), change='mloop7 (pbb): salto verso 0xB2D50 rediretto su S33_SCHEDVEC stub (tick TIMER0), rientro protetto da flag',
        limits=["Modello di laboratorio: non e' un interrupt reale", 'Serve test di esecuzione'], instrumentation=parent['instrumentation']), indent=2) + '\n')
    print(dest, sha(dest), flush=True)


if __name__ == '__main__':
    main()
