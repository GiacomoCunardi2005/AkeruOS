#!/usr/bin/env python3
"""Variante di laboratorio v17: parte dalla v16 e rende il tempo proporzionale al lavoro eseguito. Conta le istruzioni; al salto verso lo
scheduler (0xB2D50) calcola i tick maturati = (istruzioni dall'ultimo tick + resto) / periodo, con periodo = [K+0x204] (1.000.000 conteggi del
timer a 200 MHz, ipotesi: 1 istruzione = 1 conteggio), massimo 15. Se ci sono tick da emettere scrive il numero in <flag>+4 e redirige allo stub
del probe (S33_SCHEDVEC=<stub>,<flag>), che esegue il gestore TIMER0 originale; altrimenti lascia il salto intatto. Non cambia i byte Nikon."""
from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v16_brtick'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v16_brtick/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v17_timetick'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v17_timetick'
OLD = '''    if (s33_st && CPU_PBB_BR_TYPE (current_cpu) != SEM_BRANCH_UNTAKEN && CPU_PBB_BR_NPC (current_cpu) == 0xb2d50
        && (CPU_PBB_BR_NPC (current_cpu) != s33_pnpc || (int) CPU_PBB_BR_TYPE (current_cpu) != s33_ptype)) {
      /* salto appena impostato verso lo scheduler: interrupt TIMER0 modellato */
      if (GETMEMSI (current_cpu, 0, s33_sf)) SETMEMSI (current_cpu, 0, s33_sf, 0);
      else { CPU_PBB_BR_NPC (current_cpu) = s33_st; CPU_PBB_BR_TYPE (current_cpu) = SEM_BRANCH_UNCACHEABLE; }
    }
'''
OLD2 = 'execute (SIM_CPU *current_cpu, SCACHE *sc, int fast_p)\n{\n  SEM_PC vpc;\n'
OLD2 = '  IADDR s33_pnpc = CPU_PBB_BR_NPC (current_cpu); int s33_ptype = CPU_PBB_BR_TYPE (current_cpu);\n'
NEW2 = OLD2 + '  static unsigned long long s33_icount; s33_icount++;\n'
NEW = '''    if (s33_st && CPU_PBB_BR_TYPE (current_cpu) != SEM_BRANCH_UNTAKEN && CPU_PBB_BR_NPC (current_cpu) == 0xb2d50
        && (CPU_PBB_BR_NPC (current_cpu) != s33_pnpc || (int) CPU_PBB_BR_TYPE (current_cpu) != s33_ptype)) {
      /* salto verso lo scheduler: emette i tick TIMER0 maturati (tempo proporzionale alle istruzioni) */
      if (GETMEMSI (current_cpu, 0, s33_sf)) SETMEMSI (current_cpu, 0, s33_sf, 0);
      else {
        static unsigned long long s33_last, s33_carry;
        unsigned long long s33_per = (USI) GETMEMSI (current_cpu, 0, 0x1a04), s33_el = s33_icount - s33_last + s33_carry, s33_tk;
        s33_last = s33_icount;
        if (!s33_per) s33_per = 1000000;
        s33_tk = s33_el / s33_per; s33_carry = s33_el % s33_per;
        if (s33_tk > 15) { s33_tk = 15; s33_carry = 0; }
        if (s33_tk) { SETMEMSI (current_cpu, 0, s33_sf + 4, (USI) s33_tk); CPU_PBB_BR_NPC (current_cpu) = s33_st; CPU_PBB_BR_TYPE (current_cpu) = SEM_BRANCH_UNCACHEABLE; }
      }
    }
'''


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    assert not LAB.exists(), 'variante v17 gia presente'
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
    (OUT / 'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY', parent_v16_sha256=parent['experimental_sha256'], experimental_sha256=sha(dest),
        binary=str(dest), change='mloop7 (pbb): tick TIMER0 proporzionali alle istruzioni (periodo [K+0x204]), emessi al salto verso 0xB2D50 tramite lo stub S33_SCHEDVEC',
        limits=["Modello di laboratorio: non e' un interrupt reale", 'Serve test di esecuzione'], instrumentation=parent['instrumentation']), indent=2) + '\n')
    print(dest, sha(dest), flush=True)


if __name__ == '__main__':
    main()
