#!/usr/bin/env python3
"""Variante di laboratorio v8: parte dalla v7 (DSP provvisorio) e aggiunge la lettura AUX 0x48 (DC_CTRL) con valore a riposo 0 assunto.
Serve al polling `lr r1,[dc_ctrl]; btst r1,8` del flush cache Nikon (0x17FAEA). Non cambia i byte Nikon, non modifica la v7."""
from pathlib import Path
import difflib, hashlib, json, shutil, subprocess

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'work/gnu_arc700_dsp_lab_v7'
PARENT = ROOT / 'outputs/gnu_arc700_dsp/build_v7/verified_evidence.json'
HINT = ROOT / 'outputs/gnu_arc700_irq_hint/build_v1/verified_evidence.json'
LAB = ROOT / 'work/gnu_arc700_dsp_lab_v8_dcctrl'
OUT = ROOT / 'outputs/gnu_arc700_dsp/build_v8_dcctrl'
OLD = 's33_i != 0x94 && s33_i != 0x43 && s33_i != 0x200) { \\'
NEW = 's33_i != 0x94 && s33_i != 0x43 && s33_i != 0x200 && s33_i != 0x48) { \\'


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    parent = json.loads(PARENT.read_text())
    assert sha(BASE / 'install/bin/arc-elf32-run') == parent['experimental_sha256']
    instrumentation = json.loads(HINT.read_text())['instrumentation'] if 'instrumentation' in json.loads(HINT.read_text()) else parent['instrumentation']
    assert not LAB.exists(), 'variante v8 gia presente: non la ricostruisco'
    OUT.mkdir(parents=True, exist_ok=True)
    LAB.mkdir(parents=True)
    shutil.copytree(BASE / 'source', LAB / 'source', symlinks=True)
    shutil.copytree(BASE / 'build-gnu89', LAB / 'build-gnu89', symlinks=True)
    path = LAB / 'source/gnu-arc700-sim-src/sim/arc/cpu7.h'
    old = path.read_text()
    assert old.count(OLD) == 1
    new = old.replace(OLD, NEW)
    path.write_text(new)
    (OUT / 'dc_ctrl_aux.patch').write_text(''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), fromfile='v7/sim/arc/cpu7.h', tofile='v8/sim/arc/cpu7.h')))
    cmd = ['podman', 'run', '--rm', '--network', 'none', '--memory', '2g', '--volume', f'{LAB}:/work:rw', '--workdir', '/work/build-gnu89/sim/arc',
           'localhost/arc700-legacy:gcc10', 'make', '-j2', 'CFLAGS=' + instrumentation, 'run']
    (OUT / 'command.json').write_text(json.dumps(cmd, indent=2) + '\n')
    with (OUT / 'build.log').open('w') as stream:
        p = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, timeout=1500)
    assert p.returncode == 0, (OUT / 'build.log').read_text()[-3000:]
    dest = LAB / 'install/bin/arc-elf32-run'
    dest.parent.mkdir(parents=True)
    shutil.copyfile(LAB / 'build-gnu89/sim/arc/run', dest)
    dest.chmod(0o755)
    (OUT / 'verified_evidence.json').write_text(json.dumps(dict(status='BUILD_ONLY', parent_v7_sha256=parent['experimental_sha256'], experimental_sha256=sha(dest),
        binary=str(dest), change='cpu7.h: AUX 0x48 (DC_CTRL) letto come registro con valore a riposo 0 assunto (S33_AUX_LAB_RESET)',
        limits=['Assunzione di laboratorio, non modello della cache', 'Non prova il comportamento fisico del flush', 'Serve test di esecuzione'], instrumentation=instrumentation), indent=2) + '\n')
    print(dest, sha(dest), flush=True)


if __name__ == '__main__':
    main()
