#!/usr/bin/env python3
"""Variante di laboratorio v13: parte dalla v12 e aggiunge env S33_ONLY=<tcb esadecimale>: i S33_POKES sono applicati solo se il task corrente
([[0x369348]+0x1C]) e' quel TCB. Cosi' le attese del probe vengono soddisfatte ma quelle degli altri task (es. Live View) restano bloccanti.
Senza S33_ONLY il comportamento e' identico alla v12. Modello di laboratorio, non uno scheduler. Non cambia i byte Nikon."""
from pathlib import Path
import hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v12_clear'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v12_clear/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v13_curtask'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v13_curtask'
OLD_DECL = 'static int s33_init; static USI s33_a[256], s33_v[256]; static int s33_clr[256]; static int s33_cnt; static unsigned long s33_n;'
NEW_DECL = OLD_DECL + ' static USI s33_only;'
OLD_INIT = '      s33_init = 1;\n      while (s33_e && *s33_e && s33_cnt < 256) {'
NEW_INIT = '      s33_init = 1;\n      { const char *s33_o = getenv ("S33_ONLY"); if (s33_o) sscanf (s33_o, "%x", &s33_only); }\n      while (s33_e && *s33_e && s33_cnt < 256) {'
OLD_IF = '    if (s33_cnt) {\n      int s33_j;'
NEW_IF = '    if (s33_cnt && (!s33_only || GETMEMSI (current_cpu, 0, GETMEMSI (current_cpu, 0, 0x369348) + 0x1c) == s33_only)) {\n      int s33_j;'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    assert not LAB.exists(), 'variante v13 gia presente'
    OUT.mkdir(parents=True, exist_ok=True)
    shutil.copytree(BASE, LAB, symlinks=True)
    for rel in ('source/gnu-arc700-sim-src/sim/arc/mloop7.in', 'build-gnu89/sim/arc/mloop7.c'):
        p = LAB / rel
        t = p.read_text()
        for old, new in ((OLD_DECL, NEW_DECL), (OLD_INIT, NEW_INIT), (OLD_IF, NEW_IF)):
            assert t.count(old) == 1, (rel, old)
            t = t.replace(old, new)
        p.write_text(t)
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
    (OUT / 'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY', parent_v12_sha256=parent['experimental_sha256'], experimental_sha256=sha(dest),
        binary=str(dest), change='mloop7: env S33_ONLY=<tcb> -> S33_POKES solo se il task corrente e\' quel TCB',
        limits=["Modello di laboratorio: non e' uno scheduler ne' un interrupt reale", 'Serve test di esecuzione'], instrumentation=parent['instrumentation']), indent=2) + '\n')
    print(dest, sha(dest), flush=True)


if __name__ == '__main__':
    main()
