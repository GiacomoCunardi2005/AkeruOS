#!/usr/bin/env python3
"""Fase 5 (prototipo): finestra AkeruOS nel profilo basato sul dump hardware.
Oggetto finestra Nikon = flag (bit0=0) a +0, procedura a +0xC; il dispatcher originale 0x169E1C la chiama.
Il disegno usa il percorso testo Nikon originale 0x186D08. Nessun hardware; dump originale intatto."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, re, struct, subprocess, sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_run_gnu_arc700 import ROOT, TOOLCHAIN, IMAGE, sha
from s33_verify_gnu_dsp_lab import LAB, BUILD

DUMP = ROOT / 'Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN'
DUMP_SHA = 'c91888b23a8def81dc0afbf5a62a6210361308fea030bfbafcf6a43338286107'
BASE, CODE, RES, STACK_BASE = 0x100, 0x1041000, 0x3000000, 0x1048000
STACK_TOP = STACK_BASE + 16384
HI_BASE, HI_SIZE = 0x0F680000, 0x40000
CELL = 0x366EA4          # cella della finestra attiva ([[0x14579C]])
ACTIVE_ORIG = 0x783AE8   # AutoScene LiveView nel dump

ASM = '''
 .text
 .global _start
_start:
 mov sp,{stack:#x}
 mov r20,{res:#x}
 mov r0,0x1800
 mov r1,{res_k1:#x}
 mov r2,256
 bl copyw
 ; apri
 mov r0,akeru_win
 mov r1,0x7001
 mov r2,0
 mov r12,0x169e1c
 jl [r12]
 st r0,[r20,0x18]
{more}
 mov r0,0x1800
 mov r1,{res_k2:#x}
 mov r2,256
 bl copyw
 mov r0,akeru_win
 st r0,[r20,0x34]
 ld r1,[r0,0x40]
 st r1,[r20,0x38]
 ld r1,[r0,0x4c]
 st r1,[r20,0x3c]
 mov r0,{cell:#x}
 ld r0,[r0]
 st r0,[r20,0x1c]
 mov r0,akeru_win
 ld r0,[r0,0x44]
 st r0,[r20,0x20]
 mov r0,0
 mov r8,1
 trap_s 1

 .align 4
copyw:                          ; r0=src r1=dst r2=n parole
 1: ld.ab r3,[r0,4]
 st.ab r3,[r1,4]
 sub.f r2,r2,1
 bne 1b
 j [blink]
 .align 4
sumwords:                       ; r0=indirizzo r1=n parole -> r0=somma
 mov r2,0
 .align 4
1:
 ld.ab r3,[r0,4]
 add r2,r2,r3
 sub.f r1,r1,1
 bne 1b
 mov r0,r2
 j [blink]

; ---- procedura di finestra AkeruOS: r0=finestra r1=msg r2=param ----
 .align 4
akeru_proc:
 push_s blink
 push_s r13
 push_s r14
 push_s r15
 mov r13,r0
 cmp r1,0x7001
 beq do_open
 cmp r1,0x7002
 beq do_next
 cmp r1,0x7003
 beq do_close
 mov r0,0
 b out
 .align 4
do_open:
 ld r0,[r13,0x40]
 cmp r0,0
 bne reject
 mov r0,1
 st r0,[r13,0x40]
 mov r0,0
 st r0,[r13,0x44]            ; selezione
 mov r1,{cell:#x}
 ld r0,[r1]
 st r0,[r13,0x48]            ; finestra precedente
 st r13,[r1]                 ; AkeruOS diventa la finestra attiva
 bl draw_menu
 mov r0,1
 b out
 .align 4
do_next:
 ld r0,[r13,0x40]
 cmp r0,0
 beq reject
 ld r0,[r13,0x44]
 add r0,r0,1
 cmp r0,3
 bne 2f
 mov r0,0
 .align 4
2:
 st r0,[r13,0x44]
 bl draw_menu
 mov r0,1
 b out
 .align 4
do_close:
 ld r0,[r13,0x40]
 cmp r0,0
 beq reject
 mov r0,0
 st r0,[r13,0x40]
 ld r0,[r13,0x48]
 mov r1,{cell:#x}
 st r0,[r1]                  ; ripristina la finestra precedente
 mov r0,1
 b out
 .align 4
reject:
 ld r0,[r13,0x4c]
 add r0,r0,1
 st r0,[r13,0x4c]   ; contatore dei rifiuti
 mov r0,0
 .align 4
out:
 pop_s r15
 pop_s r14
 pop_s r13
 pop_s blink
 j [blink]

 .align 4
draw_menu:                      ; ridisegna le 3 voci, evidenziando la selezione
 push_s blink
 mov r15,0
 .align 4
dm_loop:
 mov r0,10
 mov r2,300
 mov r1,r15
 asl r1,r1,5
 add r1,r1,20               ; y0 = 20 + 32*i
 add r3,r1,24
 mov r4,akeru_win
 ld r4,[r4,0x44]
 cmp r4,r15
 mov r5,0x00808080
 mov.eq r5,0x00ffffff
 asl r4,r15,2
 add r4,r4,items
 ld r4,[r4]
 mov r6,0
 mov r12,0x186d08
 jl [r12]
 mov r4,akeru_win
 ld r4,[r4,0x44]
 cmp r4,r15
 bne no_mark
 mov r1,r15
 asl r1,r1,5
 add r1,r1,20
 add r3,r1,24
 mov r0,0
 mov r2,9
 mov r4,markstr
 mov r5,0x00ffffff
 mov r6,0
 mov r12,0x186d08
 jl [r12]
no_mark:
 add r15,r15,1
 cmp r15,3
 bne dm_loop
 pop_s blink
 j [blink]

markstr: .asciz ">"
item0: .asciz "Esposizione"
item1: .asciz "Colore / Mono RAW"
item2: .asciz "Impostazioni"
 .align 4
items: .word item0,item1,item2
 .align 4
akeru_win:
 .word 0                     ; +0x00 flag (bit0=0: procedura a +0xC)
 .word 0,0
 .word akeru_proc            ; +0x0C procedura di finestra
 .space 0x30                 ; +0x10..+0x3F
 .word 0                     ; +0x40 aperta
 .word 0                     ; +0x44 selezione
 .word 0                     ; +0x48 finestra precedente
 .word 0                     ; +0x4C rifiuti
 .section .stack,"aw",@nobits
 .align 16
 .space 16384
'''

def build_run(stage, out):
    more = ''
    if stage >= 2:
        more += ' mov r0,akeru_win\n mov r1,0x7001\n mov r2,0\n mov r12,0x169e1c\n jl [r12]\n st r0,[r20,0x24]   ; riapertura: deve essere rifiutata\n'
        more += ' mov r0,akeru_win\n mov r1,0x7002\n mov r2,0\n mov r12,0x169e1c\n jl [r12]\n st r0,[r20,0x28]\n'
    if stage >= 3:
        more += ' mov r0,akeru_win\n mov r1,0x7003\n mov r2,0\n mov r12,0x169e1c\n jl [r12]\n st r0,[r20,0x2c]\n'
    raw = DUMP.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DUMP_SHA
    (out / 'probe.s').write_text(ASM.format(stack=STACK_TOP, res=RES, cell=CELL, more=more, res_k1=RES + 0x100, res_k2=RES + 0x500))
    (out / 'ram_working_copy.bin').write_bytes(raw[BASE:])
    (out / 'image.ld').write_text(f'PHDRS {{ ram PT_LOAD FLAGS(7); stk PT_LOAD FLAGS(6); }}\nSECTIONS {{\n . = {BASE:#x}; .dumpram : {{ *(.dumpram) }} :ram\n . = {CODE:#x}; .text : {{ *(.text) }} :ram\n . = {STACK_BASE:#x}; .stack (NOLOAD) : {{ *(.stack) }} :stk\n}}\n')
    for cmd in ([TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL', '-o', out / 'probe.o', out / 'probe.s'],
                [TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc', '--rename-section', '.data=.dumpram,alloc,load,contents', out / 'ram_working_copy.bin', out / 'ram.o'],
                [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-e', hex(CODE), '-T', out / 'image.ld', '-o', out / 'image.elf', out / 'probe.o', out / 'ram.o']):
        pr = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
        assert pr.returncode == 0, pr.stderr
    (out / 'result.bin').write_bytes(bytes(0x1000))
    (out / 'hi_ram.bin').write_bytes(bytes(HI_SIZE))
    assert sha(LAB / 'install/bin/arc-elf32-run') == json.loads(BUILD.read_text())['experimental_sha256']
    cmd = ['podman', 'run', '--rm', '--network', 'none', '--memory', '2g', '--volume', f'{LAB}:/engine:ro', '--volume', f'{out}:/result:rw', IMAGE,
           'timeout', '120s', '/engine/install/bin/arc-elf32-run',
           '--memory-mapfile', '/result/result.bin', '--memory-region', f'{RES:#x},4096',
           '--memory-mapfile', '/result/hi_ram.bin', '--memory-region', f'{HI_BASE:#x},{HI_SIZE:#x}', '/result/image.elf']
    run = subprocess.run(cmd, capture_output=True, text=True, timeout=400)
    (out / 'sim.log').write_text(run.stdout + run.stderr)
    rb = (out / 'result.bin').read_bytes(); res = struct.unpack('<16I', rb[:64]); k1 = rb[0x100:0x500]; k2 = rb[0x500:0x900]
    return run.returncode, res, (out / 'hi_ram.bin').read_bytes(), k1, k2

def main():
    root = ROOT / 'Risultati/Runtime_Kernel/Akeru_Window_Profile' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    stages = {}
    for stage in (1, 2, 3):
        out = root / f'stage{stage}'
        out.mkdir(parents=True)
        rc, res, hi, k1, k2 = build_run(stage, out)
        kdiff = [(0x1800 + 4 * i, struct.unpack_from('<I', k1, 4 * i)[0], struct.unpack_from('<I', k2, 4 * i)[0]) for i in range(256) if k1[4 * i:4 * i + 4] != k2[4 * i:4 * i + 4]]
        nz = [i for i, b in enumerate(hi) if b]
        stages[stage] = dict(exit=rc, kernel_diff=[(hex(a), hex(b), hex(c)) for a, b, c in kdiff], flag=res[14], rejects=res[15], win=hex(res[13]),
                             active_cell=hex(res[7]), selection=res[8], pixels=len(nz), values=sorted({hi[i] for i in nz}), hi=hi)
    h1, h2, h3 = stages[1]['hi'], stages[2]['hi'], stages[3]['hi']
    diff12 = sum(1 for a, b in zip(h1, h2) if a != b)
    s1, s2, s3 = stages[1], stages[2], stages[3]
    ok = (all(s['exit'] == 0 for s in stages.values())
          and s1['flag'] == 1 and s1['active_cell'] == s1['win'] and s1['pixels'] > 0
          and s2['rejects'] == 1 and s2['selection'] == 1 and diff12 > 0
          and s3['flag'] == 0 and s3['active_cell'] == hex(ACTIVE_ORIG))
    for k, s in stages.items():
        s.pop('hi')
    ev = dict(status='PASS' if ok else 'FAIL', dump_sha256=DUMP_SHA, stages=stages, pixel_diff_open_vs_next=diff12,
              limits='Apertura/chiusura eseguite dalla procedura (non dal manager Nikon); DSP provvisorio; MMIO/scheduler non emulati; piano pixel in RAM alta ricostruito da zeri; palette non decodificata.')
    (root / 'evidence.json').write_text(json.dumps(ev, indent=2) + '\n')
    # immagini PNG per fase: piano a 8 bit, 640 byte per riga (y conta mezze righe); la colonna d'origine dipende
    # dalla base ignota del piano, quindi si sceglie lo shift circolare che rende minima la larghezza.
    from PIL import Image
    S = 640
    for stage, h in ((1, h1), (2, h2), (3, h3)):
        nz = [i for i, b in enumerate(h) if b]
        best = min((max(((i % S) - sh) % S for i in nz) - min(((i % S) - sh) % S for i in nz), sh) for sh in range(S))
        w, sh = best
        mn = min(((i % S) - sh) % S for i in nz)
        rows = sorted({i // S for i in nz})
        im = Image.new('L', (w + 1, rows[-1] - rows[0] + 1), 0)
        px = im.load()
        for i in nz:
            px[((i % S) - sh) % S - mn, i // S - rows[0]] = min(255, h[i] * 7)
        im.resize(((w + 1) * 3, (rows[-1] - rows[0] + 1) * 3), Image.NEAREST).save(root / f'stage{stage}' / 'menu.png')
    assert hashlib.sha256(DUMP.read_bytes()).hexdigest() == DUMP_SHA, 'originale modificato'
    print(ev['status'], json.dumps({k: {x: y for x, y in v.items() if x not in ('values',)} for k, v in stages.items()}), 'diff', diff12, root)
    sys.exit(0 if ok else 1)

if __name__ == '__main__':
    main()
