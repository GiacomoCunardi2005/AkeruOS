#!/usr/bin/env python3
"""LATCH TARGETS DELLA CALLBACK TASTI 0x16E588 (it.54, punto it.52(a)):
0x16ED40 (uniche 2 bl al mondo DENTRO 0x16E588) e 0x16F070 (sito 0x16E692
piu' famiglia 0x16ECEC/0x16EE26). Decodifica statica + 11 casi CPU su
byte ORIGINALI (motore pinnato GNU ARC700).

Scoperte centrali (statiche, provate qui in CPU):
- 0x16ED40 e' lo SCRITTORE DI DUMP "\\\\MEMDUMP.BIN": prologo push_s blink +
  millicode 0x334130 + frame 276 byte; bl 0xCB5E4 (ritorno scartato, come
  la maggior parte dei 12+ chiamanti della getter); r14=fp-276 (buffer);
  bl 0x12B0DC(buffer); bl 0x32DE00(buffer, 0x34848C) con 0x34848C =
  stringa ASCII "\\MEMDUMP.BIN" nel dump; bl 0xAD920(fp-0x20, 0, 256)
  (azzeramento area 256 byte); bl 0x12BD5C(buffer, fp-0x20, 256, 1):
  se ritorna 0 riprova bl 0x12BD5C(buffer, 256, 0x104064C, 1); bl 0xCB5B0
  (ritorno scartato); cmp r13 (risultato dell'ULTIMO 0x12BD5C eseguito):
  0 -> bl 0x1567F8(0x64, 0x64, 0x393044="Write ok!") senza r3;
  != 0 -> bl 0x1567F8(0x64, 0x64, 0x39304E="Write fail %X", r13).
  Epilogo mov sp,fp + ld.ab fp + b 0x33419C. L'ARGOMENTO r0 in ingresso
  (byte[0x36726B] nel sito 0x16E5B8, evento nel sito 0x16E616) e' MORTO.
- La cella r13: ASSUNZIONE (a) documentata: 0xCB5B0 preserva r13 e il
  verdetto ok/fail e' il ritorno di 0x12BD5C (le stringhe e r3=r13 al log
  coerenti). Alternativa (b) APERTA: 0xCB5B0 restituisce in r13 (tail
  0xCA384 fuori dalle finestre; micro-test tmp/it54/micro_cb5b0_*:
  layout push_s blink a 0xCB5B0, ld.as a 0xCB5B2, path stato 0 ->
  0x16BBB8 -> b_s 0xCB5E0 -> b 0xCA384). NON risolto in CPU qui.
- 0x16F070(arg): byte[0x367898] := arg (pool 0x16F0E4 = 0x367898: la
  cella byte[+0] del latch ctx, scritta SOLO qui) e poi 15 chiamate
  indirette jl_s [r14] con r14 = pool 0x16F0E8 = 0x16F950 e
  (r0=classe, r1=arg) per le classi
  {1,2,5,6,7,8,9,0xA,0xB,0xC,0xE,0xF,0x43,3,0x4E} — inclusive dei
  QUATTRO SLOT AKERUOS 0xB=11 (0x580), 0xE=14 (0x700), 0x43=67 (0x2180),
  0x4E=78 (0x2700); tail b 0x16EE68 (epilogo condiviso). E' l'ARM/DISARM
  del gate ring per classe.
- 0x16F950(classe, flag) REALE (leaf, 0 bl): r2 = 0x446808 (pool
  0x16FA34) + 4*classe (add2_s); halfword[record+2]: flag!=0 -> bset
  bit0, flag==0 -> bclr bit0; stw halfword[record+2]; ritorno j_s.d
  [blink] con delay slot stw. E' il bit0 che il fan-out 0x16F6B0
  richiede (via 0x16F6A4) per inserire l'evento nell'anello 0x17BC7C.
- Il corpo della callback chiama 0x16F070(1) per evento 0x3100 quando
  NON vale il percorso modo 0x15 (it.52): CHAIN provata in CPU
  callback reale -> 0x16F070 reale -> 0x16F950 reale.
- NESSUNA LE di 0x16ED40/0x16F070 nei 16 payload; LE 0x16F950 = 6
  (pool 0x16F0E8 + 0x135B2C + 4 in p2: 0x6403B4/0x6430C0/0x658998/
  0x65D2A0, candidati pool indiretti NON decodificati); bl 0x16F950 =
  7 siti (it.51 confermato).

Casi CPU (11, byte ORIGINALI .cb/.ed40/.f070/.f950/.kmach/.epi + query
0x16F920 e getter modo 0xCAD30 ORIGINALI): ed40_write_ok, ed40_write_fail,
ed40_second_then_ok, ed40_two_then_fail (stub 12BD5C a due celle),
f070_arm_real + f070_disarm_real (0x16F950 REALE: bit0 di 15 classi
set/clr con bit1 preservato, classi fuori lista intatte),
f070_order_stub (sequenza esatta delle 15 classi),
cb3100_arm_chain (callback->0x16F070->0x16F950 tutte reali),
latch8_2701_memdump_chain (callback reale -> 0x16ED40 reale ->
"Write ok!" con stub I/O), latch9_2701_memdump_chain,
latch8_cell26b_zero_negative (0x16ED40 NON chiamato, corpo principale).

RAM sintetiche: latch 0x367898/0x3678A0/A1, 0x36726B, mode 0xC8E80C,
record tasti 0x446808 (gap del dump). Stub con log per tutte le funzioni
esterne. NESSUN hardware; NON_INSTALLARE.
"""
import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_trace_state_dispatch import verified_payloads
from s33_run_gnu_arc700 import ROOT, LEGACY, TOOLCHAIN, Runner, sha, elf_loads

LISTING = ROOT / 'Risultati/Disassemblati/Firmware1.1.asm'
STACK = 0xC8F000
LOG = 0x367000
PROBE_AT = 0x300000
EVADDR = 0x367700

RETVAL = LOG + 0x10
RET_C9BF8 = LOG + 0x20
RET_BC90 = LOG + 0x24
RET_D0CA4 = LOG + 0x28
RET_CB618 = LOG + 0x2C
RET_12B_A = LOG + 0x50
RET_12B_B = LOG + 0x54
CNT_C9BF8 = LOG + 0x30
CNT_BC90 = LOG + 0x34
CNT_D0CA4 = LOG + 0x38
CNT_C68F0 = LOG + 0x3C
CNT_CB618 = LOG + 0x40
CNT_ED40 = LOG + 0x44
CNT_F070 = LOG + 0x48
CNT_CB5E4 = LOG + 0x60
CNT_12B0DC = LOG + 0x64
CNT_32DE00 = LOG + 0x68
CNT_AD920 = LOG + 0x6C
CNT_12BD5C = LOG + 0x70
CNT_CB5B0 = LOG + 0x74
CNT_1567F8 = LOG + 0x78
CNT_F950 = LOG + 0x7C
POST_COUNT = LOG + 0x80
POST_ENT = LOG + 0x90
L_32DE00 = LOG + 0x100
L_AD920 = LOG + 0x110
L_12B1 = LOG + 0x120
L_12B2 = LOG + 0x130
L_1567F8 = LOG + 0x140
F950_LOG = LOG + 0x150

LATCH0 = 0x367898          # byte[+0] del ctx latch (scritto da 0x16F070)
LATCH8 = 0x3678A0
LATCH9 = 0x3678A1
CELL26B = 0x36726B
MODECELL = 0xC8E80C
RECBASE = 0x446808

F070_IDS = [1, 2, 5, 6, 7, 8, 9, 0xA, 0xB, 0xC, 0xE, 0xF, 0x43, 3, 0x4E]
F070_NEG = [4, 13, 0x62, 0x65, 0x66, 0x77, 118]   # classi NON nella lista

W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_CB = (0, 0x16E588, 0x16E6E0, '.cb')
W_ED40 = (0, 0x16ED40, 0x16EDDC, '.ed40')        # include pool 0x16EDCC..DB
W_F070 = (0, 0x16F070, 0x16F0EC, '.f070')        # include pool 0x16F0E4/E8
W_F950 = (0, 0x16F950, 0x16F966, '.f950')        # leaf, delay slot 0x16F964
W_F950POOL = (0, 0x16FA34, 0x16FA38, '.f950pool')  # pool 0x16FA34 = 0x446808
W_EPI = (0, 0x16EE68, 0x16EE74, '.epi')          # epilogo condiviso 0x16F070
W_KMACH = (0, 0x16F630, 0x16FA60, '.kmach')
W_MODEGET = (0, 0xCAD30, 0xCAD38, '.modeget')
W_MODEPOOL = (0, 0xCAAC0, 0xCAAD0, '.modepool')

POOL_WORDS = {
    0x16E6D8: 0x367898, 0x16E6DC: 0x36726B, 0xCAAC4: 0xC8E80C,
    0x16EDCC: 0x34848C, 0x16EDD0: 0x104064C, 0x16EDD4: 0x393044,
    0x16EDD8: 0x39304E, 0x16F0E4: 0x367898, 0x16F0E8: 0x16F950,
    0x16FA34: 0x446808,
}
STR_DUMP = [
    (0x34848C, b'\\MEMDUMP.BIN\x00'),
    (0x393044, b'Write ok!\x00'),
    (0x39304E, b'Write fail %X\x00'),
]

CENSUS = {
    0x16ED40: [0x16E5B8, 0x16E616],
    0x16F070: [0x16E692, 0x16ECEC, 0x16EE26],
    0x16F950: [0x2B37CC, 0x2CA34C, 0x2CABCC, 0x2CAC64, 0x2CBB28,
               0x6531DE, 0x6531E6],
    0x1567F8: [0x16EDAC, 0x16EDBA],
    0x12BD5C: [0x16ED84, 0x16ED98],
    0x32DE00: [0x16ED66],
    0x12B0DC: [0x16ED5E],
    0xAD920: [0x16ED76],
    0xCB5E4: [0x16ED52],
    0xCB5B0: [0x16ED9E],
}
LE_16F950 = [(0, 0x135B2C), (0, 0x16F0E8), (2, 0x6403B4), (2, 0x6430C0),
             (2, 0x658998), (2, 0x65D2A0)]


def post_entry(k, r0, r1, r2):
    return [(POST_ENT + 16 * k + 0, 4, r0),
            (POST_ENT + 16 * k + 4, 4, r1),
            (POST_ENT + 16 * k + 8, 4, r2)]


def rec_flags(classes, val):
    t = []
    for c in classes:
        t.append(f' mov r0,{hex(val)}\n'
                 f' mov r1,{hex(RECBASE + 4 * c + 2)}\n sth r0,[r1,0]\n')
    return ''.join(t)


def presets(mode=0x2C, ret_c9bf8=1, ret_bc90=0, ret_d0ca4=0,
            ret_cb618=0, latch8=0, latch9=0, cell26b=0,
            recs=(), ret_12b_a=1, ret_12b_b=1):
    t = [f' mov r0,{hex(mode)}\n mov r1,{hex(MODECELL)}\n stb r0,[r1,0]\n',
         f' mov r0,{hex(ret_c9bf8)}\n mov r1,{hex(RET_C9BF8)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(ret_bc90)}\n mov r1,{hex(RET_BC90)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(ret_d0ca4)}\n mov r1,{hex(RET_D0CA4)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(ret_cb618)}\n mov r1,{hex(RET_CB618)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(latch8)}\n mov r1,{hex(LATCH8)}\n stb r0,[r1,0]\n',
         f' mov r0,{hex(latch9)}\n mov r1,{hex(LATCH9)}\n stb r0,[r1,0]\n',
         f' mov r0,{hex(cell26b)}\n mov r1,{hex(CELL26B)}\n stb r0,[r1,0]\n',
         f' mov r0,{hex(ret_12b_a)}\n mov r1,{hex(RET_12B_A)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(ret_12b_b)}\n mov r1,{hex(RET_12B_B)}\n st r0,[r1,0]\n']
    for classe, stato in recs:
        t.append(f' mov r0,{hex(stato)}\n'
                 f' mov r1,{hex(RECBASE + 4 * classe)}\n stb r0,[r1,0]\n')
    return ''.join(t)


def call_cb(classe, stato, event):
    return (f' mov r0,{hex(event)}\n mov r1,{hex(EVADDR)}\n sth r0,[r1,0]\n'
            f' mov r0,{hex(classe)}\n mov r1,{hex(stato)}\n'
            f' mov r2,{hex(EVADDR)}\n mov r12,0x16e588\n jl_s [r12]\n'
            f' mov r1,{hex(RETVAL)}\n st r0,[r1,0]\n')


def call_f070(arg):
    return (f' mov r0,{hex(arg)}\n mov r12,0x16f070\n jl_s [r12]\n'
            f' mov r1,{hex(RETVAL)}\n st r0,[r1,0]\n')


ARM = rec_flags(F070_IDS, 2) + rec_flags(F070_NEG, 2)


# ------------------------------------------------------------------ casi --
def ed40_common():
    return [W_ED40, W_MILI]


ED40_STUBS = ['s_c9bf8', 's_bc90', 's_d0ca4', 's_cb618', 's_c68f0',
              's_post', 's_f070', 's_f950', 's_cb5e4',
              's_12b0dc', 's_32de00', 's_ad920', 's_12bd5c', 's_cb5b0',
              's_1567f8']

CPU_SPECS = [
    # NB: il primo 0x12BD5C ritorna 0 -> SECONDO tentativo (0x104064C);
    # il verdetto e' r13 = ritorno dell'ULTIMO 0x12BD5C: 0 -> "Write ok!",
    # != 0 -> "Write fail %X" con r13 in r3.
    dict(name='ed40_two_calls_write_ok',
         extra=presets(ret_12b_a=0, ret_12b_b=0)
         + ' mov r12,0x16ed40\n jl_s [r12]\n'
         + f' mov r1,{hex(RETVAL)}\n st r0,[r1,0]\n',
         windows=ed40_common(), stubs=ED40_STUBS,
         asserts=[(CNT_CB5E4, 4, 1), (CNT_12B0DC, 4, 1),
                  (CNT_32DE00, 4, 1), (CNT_AD920, 4, 1),
                  (CNT_12BD5C, 4, 2), (CNT_CB5B0, 4, 1),
                  (CNT_1567F8, 4, 1),
                  (L_32DE00 + 4, 4, 0x34848C),
                  (L_AD920 + 4, 4, 0), (L_AD920 + 8, 4, 256),
                  (L_12B1 + 8, 4, 256), (L_12B1 + 12, 4, 1),
                  (L_12B2 + 4, 4, 256), (L_12B2 + 8, 4, 0x104064C),
                  (L_12B2 + 12, 4, 1),
                  (L_1567F8, 4, 0x64), (L_1567F8 + 4, 4, 0x64),
                  (L_1567F8 + 8, 4, 0x393044)],
         success=0xDEADB001),
    dict(name='ed40_first_fail',
         extra=presets(ret_12b_a=0xDEAD0005)
         + ' mov r12,0x16ed40\n jl_s [r12]\n'
         + f' mov r1,{hex(RETVAL)}\n st r0,[r1,0]\n',
         windows=ed40_common(), stubs=ED40_STUBS,
         asserts=[(CNT_12BD5C, 4, 1), (CNT_1567F8, 4, 1),
                  (L_12B2, 4, 0),
                  (L_1567F8 + 8, 4, 0x39304E),
                  (L_1567F8 + 12, 4, 0xDEAD0005)],
         success=0xDEADB002),
    dict(name='ed40_second_fail',
         extra=presets(ret_12b_a=0, ret_12b_b=0xDEAD0006)
         + ' mov r12,0x16ed40\n jl_s [r12]\n'
         + f' mov r1,{hex(RETVAL)}\n st r0,[r1,0]\n',
         windows=ed40_common(), stubs=ED40_STUBS,
         asserts=[(CNT_12BD5C, 4, 2), (CNT_1567F8, 4, 1),
                  (L_1567F8 + 8, 4, 0x39304E),
                  (L_1567F8 + 12, 4, 0xDEAD0006)],
         success=0xDEADB003),
    dict(name='f070_arm_real',
         extra=ARM + call_f070(1),
         windows=[W_F070, W_F950, W_F950POOL, W_EPI, W_MILI],
         stubs=['s_c9bf8', 's_bc90', 's_d0ca4', 's_cb618', 's_c68f0',
                's_post', 's_ed40'],
         asserts=[(LATCH0, 1, 1)]
         + [(RECBASE + 4 * c + 2, 2, 3) for c in F070_IDS]
         + [(RECBASE + 4 * c + 2, 2, 2) for c in F070_NEG],
         success=0xDEADB005),
    dict(name='f070_disarm_real',
         extra=(rec_flags(F070_IDS, 3) + rec_flags(F070_NEG, 3)
                + call_f070(0)),
         windows=[W_F070, W_F950, W_F950POOL, W_EPI, W_MILI],
         stubs=['s_c9bf8', 's_bc90', 's_d0ca4', 's_cb618', 's_c68f0',
                's_post', 's_ed40'],
         asserts=[(LATCH0, 1, 0)]
         + [(RECBASE + 4 * c + 2, 2, 2) for c in F070_IDS]
         + [(RECBASE + 4 * c + 2, 2, 3) for c in F070_NEG],
         success=0xDEADB006),
    dict(name='f070_order_stub',
         extra=ARM + call_f070(1),
         windows=[W_F070, W_EPI, W_MILI],
         stubs=['s_c9bf8', 's_bc90', 's_d0ca4', 's_cb618', 's_c68f0',
                's_post', 's_ed40', 's_f950'],
         asserts=[(CNT_F950, 4, 15), (LATCH0, 1, 1)]
         + [(F950_LOG + 8 * k, 4, F070_IDS[k]) for k in range(15)]
         + [(F950_LOG + 8 * k + 4, 4, 1) for k in range(15)],
         success=0xDEADB007),
    dict(name='cb3100_arm_chain',
         extra=presets() + ARM + call_cb(98, 1, 0x3100),
         windows=[W_CB, W_F070, W_EPI, W_KMACH, W_MILI,
                  W_MODEGET, W_MODEPOOL],  # .kmach copre 0x16F950+pool
         stubs=['s_c9bf8', 's_bc90', 's_d0ca4', 's_cb618', 's_c68f0',
                's_post', 's_ed40'],
         asserts=[(RETVAL, 4, 0), (POST_COUNT, 4, 0), (CNT_ED40, 4, 0),
                  (CNT_D0CA4, 4, 0), (LATCH0, 1, 1),
                  (LATCH8, 1, 0), (LATCH9, 1, 0)]
         + [(RECBASE + 4 * c + 2, 2, 3) for c in F070_IDS]
         + [(RECBASE + 4 * c + 2, 2, 2) for c in F070_NEG],
         success=0xDEADB008),
    dict(name='latch8_2701_memdump_chain',
         extra=presets(latch8=1, cell26b=1, ret_12b_a=0, ret_12b_b=0)
         + call_cb(78, 0, 0x2701),
         windows=[W_CB, W_ED40, W_EPI, W_KMACH, W_MILI, W_MODEGET,
                  W_MODEPOOL],
         stubs=['s_c9bf8', 's_bc90', 's_d0ca4', 's_cb618', 's_c68f0',
                's_post', 's_f070', 's_cb5e4', 's_12b0dc',  # s_f950: .kmach reale
                's_32de00', 's_ad920', 's_12bd5c', 's_cb5b0', 's_1567f8'],
         asserts=[(RETVAL, 4, 0), (LATCH8, 1, 0), (LATCH9, 1, 0),
                  (POST_COUNT, 4, 0), (CNT_1567F8, 4, 1),
                  (CNT_32DE00, 4, 1), (CNT_12B0DC, 4, 1),
                  (CNT_AD920, 4, 1), (CNT_12BD5C, 4, 2),
                  (CNT_CB5E4, 4, 1), (CNT_CB5B0, 4, 1),
                  (CNT_F070, 4, 0), (CNT_F950, 4, 0),
                  (L_32DE00 + 4, 4, 0x34848C),
                  (L_1567F8 + 8, 4, 0x393044)],
         success=0xDEADB009),
    dict(name='latch9_2701_memdump_fail_chain',
         extra=presets(latch8=1, latch9=1, cell26b=0,
                       ret_12b_a=0xDEAD0007,
                       recs=((9, 1),)) + call_cb(9, 0, 0x2701),
         windows=[W_CB, W_ED40, W_EPI, W_KMACH, W_MILI, W_MODEGET,
                  W_MODEPOOL],
         stubs=['s_c9bf8', 's_bc90', 's_d0ca4', 's_cb618', 's_c68f0',
                's_post', 's_f070', 's_cb5e4', 's_12b0dc',  # s_f950: .kmach reale
                's_32de00', 's_ad920', 's_12bd5c', 's_cb5b0', 's_1567f8'],
         asserts=[(RETVAL, 4, 0), (LATCH8, 1, 0), (LATCH9, 1, 0),
                  (POST_COUNT, 4, 0), (CNT_1567F8, 4, 1),
                  (CNT_12BD5C, 4, 1),
                  (L_32DE00 + 4, 4, 0x34848C),
                  (L_1567F8 + 8, 4, 0x39304E),
                  (L_1567F8 + 12, 4, 0xDEAD0007)],
         success=0xDEADB00A),
    dict(name='latch8_cell26b_zero_negative',
         extra=presets(latch8=1, cell26b=0, ret_cb618=0,
                       recs=((0x4E, 0), (9, 0)))
         + call_cb(78, 0, 0x2701),
         windows=[W_CB, W_KMACH, W_MILI, W_MODEGET, W_MODEPOOL],
         stubs=['s_c9bf8', 's_bc90', 's_d0ca4', 's_cb618', 's_c68f0',
                's_post', 's_ed40', 's_f070'],  # s_f950: .kmach reale
         asserts=[(RETVAL, 4, 0), (CNT_ED40, 4, 0), (CNT_F070, 4, 0),
                  (LATCH8, 1, 1), (POST_COUNT, 4, 1)]
         + post_entry(0, 0, 0x4006, 78),
         success=0xDEADB00B),
]


# ------------------------------------------------------------------ asm ----
def harness(extra):
    return ('.section .text,"ax",@progbits\n.global _start\n_start:\n'
            f' mov sp,{hex(STACK)}\n'
            + extra +
            f' mov r12,{hex(PROBE_AT)}\n'
            ' j_s [r12]\n'
            '.section .log,"aw",@progbits\n.align 4\n .space 2048\n'
            '.section .stack,"aw",@nobits\n.align 16\n .space 16384\n')


def stub_ret(sec, count_cell, ret_cell):
    return (f'.section {sec},"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(count_cell)}\n'
            ' ld r4,[r3,0]\n add r5,r4,1\n st r5,[r3,0]\n'
            f' mov r3,{hex(ret_cell)}\n ld r0,[r3,0]\n'
            ' pop_s blink\n j_s [blink]\n')


def stub_count(sec, count_cell):
    return (f'.section {sec},"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(count_cell)}\n'
            ' ld r4,[r3,0]\n add r5,r4,1\n st r5,[r3,0]\n'
            ' mov r0,0\n'
            ' pop_s blink\n j_s [blink]\n')


def stub_args(sec, count_cell, fields_base, nfields, ret_cells=None):
    body = (f'.section {sec},"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r7,{hex(count_cell)}\n'
            ' ld r4,[r7,0]\n add r5,r4,1\n st r5,[r7,0]\n'
            f' mov r6,{hex(fields_base - 0x10)}\n'
            ' asl r8,r5,4\n add r6,r6,r8\n')
    offs = {2: [0, 4], 3: [0, 4, 8], 4: [0, 4, 8, 12]}[nfields]
    regs = ['r0', 'r1', 'r2', 'r3'][:nfields]
    for reg, off in zip(regs, offs):
        body += f' st {reg},[r6,{hex(off)}]\n'
    if ret_cells is None:
        body += ' mov r0,0\n'
    else:
        cell_a, cell_b = ret_cells
        body += (f' cmp r4,0\n bne 2f\n'
                 f' mov r7,{hex(cell_a)}\n b_s 3f\n'
                 f'2: mov r7,{hex(cell_b)}\n'
                 f'3: ld r0,[r7,0]\n')
    body += ' pop_s blink\n j_s [blink]\n'
    return body


def stub_f950():
    return ('.section .s_f950,"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(CNT_F950)}\n'
            ' ld r4,[r3,0]\n add r5,r4,1\n st r5,[r3,0]\n'
            f' mov r6,{hex(F950_LOG)}\n'
            ' asl r7,r4,3\n add r6,r6,r7\n'
            ' st r0,[r6,0]\n st r1,[r6,4]\n'
            ' mov r0,0\n'
            ' pop_s blink\n j_s [blink]\n')


def stub_post():
    return ('.section .s_post,"ax",@progbits\n .org 0\n'
            ' push_s blink\n'
            f' mov r3,{hex(POST_COUNT)}\n'
            ' ld r4,[r3,0]\n add r5,r4,1\n st r5,[r3,0]\n'
            ' asl r6,r4,4\n add r6,r6,r3\n add r6,r6,16\n'
            ' st r0,[r6,0]\n st r1,[r6,4]\n st r2,[r6,8]\n'
            ' mov r0,0\n pop_s blink\n j_s [blink]\n')


def probe(asserts, success, case_idx):
    text = []
    n = 0
    for addr, width, expected in asserts:
        text.append(f' mov r4,{hex(addr)}')
        text.append(' ldb r5,[r4,0]' if width == 1
                    else ' ldh r5,[r4,0]' if width == 2
                    else ' ld r5,[r4,0]')
        text.append(f' mov r6,{hex(expected)}')
        text.append(' cmp r5,r6')
        text.append(f' bne bad{n}')
        n += 1
    text.append(f' mov r5,{hex(success)}')
    text.append(' ldb r0,[r5,0]')
    for k in range(n):
        marker = 0xDEAD0000 + case_idx * 0x80 + k
        text.append(f'bad{k}:')
        text.append(f' mov r5,{hex(marker)}')
        text.append(' ldb r0,[r5,0]')
    return ('.section .probe,"ax",@progbits\n .org 0\n'
            + '\n'.join(text) + '\n')


STUB_LIB = {
    's_c9bf8': ('.s_c9bf8', 0xC9BF8, lambda: stub_ret('.s_c9bf8', CNT_C9BF8, RET_C9BF8)),
    's_bc90': ('.s_bc90', 0x16BC90, lambda: stub_ret('.s_bc90', CNT_BC90, RET_BC90)),
    's_d0ca4': ('.s_d0ca4', 0xD0CA4, lambda: stub_ret('.s_d0ca4', CNT_D0CA4, RET_D0CA4)),
    's_cb618': ('.s_cb618', 0xCB618, lambda: stub_ret('.s_cb618', CNT_CB618, RET_CB618)),
    's_c68f0': ('.s_c68f0', 0xC68F0, lambda: stub_count('.s_c68f0', CNT_C68F0)),
    's_ed40': ('.s_ed40', 0x16ED40, lambda: stub_count('.s_ed40', CNT_ED40)),
    's_f070': ('.s_f070', 0x16F070, lambda: stub_count('.s_f070', CNT_F070)),
    's_f950': ('.s_f950', 0x16F950, stub_f950),
    's_cb5e4': ('.s_cb5e4', 0xCB5E4, lambda: stub_count('.s_cb5e4', CNT_CB5E4)),
    's_12b0dc': ('.s_12b0dc', 0x12B0DC, lambda: stub_count('.s_12b0dc', CNT_12B0DC)),
    's_32de00': ('.s_32de00', 0x32DE00, lambda: stub_args('.s_32de00', CNT_32DE00, L_32DE00, 2)),
    's_ad920': ('.s_ad920', 0xAD920, lambda: stub_args('.s_ad920', CNT_AD920, L_AD920, 3)),
    's_12bd5c': ('.s_12bd5c', 0x12BD5C, lambda: stub_args('.s_12bd5c', CNT_12BD5C, L_12B1, 4, (RET_12B_A, RET_12B_B))),
    's_cb5b0': ('.s_cb5b0', 0xCB5B0, lambda: stub_ret('.s_cb5b0', CNT_CB5B0, RET_BC90)),
    's_1567f8': ('.s_1567f8', 0x1567F8, lambda: stub_args('.s_1567f8', CNT_1567F8, L_1567F8, 4)),
    's_post': ('.s_post', 0x169EB4, stub_post),
}
RAM_SECTIONS = [
    ('.kmram', 0x446800, 0x240),
    ('.latram', 0x367890, 0x20),
    ('.l26b', 0x367260, 0x18),
    ('.modecell', 0xC8E808, 0x8),
]


# ------------------------------------------------------------- static ----
CALL_RE = re.compile(r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| '
                     r'(bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+'
                     r';0x(16ed40|16f070|16f950|1567f8|12bd5c|32de00|'
                     r'12b0dc|ad920|cb5e4|cb5b0|16f72c)\b')


def payload_of(blocks, addr):
    for b in blocks:
        if b['load_address_candidate'] <= addr \
                < b['load_address_candidate'] + b['size']:
            return b['index']
    return None


def parse_f070_ids(data):
    """Estrae dal corpo 0x16F070 le chiamate jl_s [r14] e restituisce
    gli id r0 in ordine. Primo call: mov_s r0,1 (01 d8) + jl_s (40 7e)
    SENZA mov_s r1,r13 (gia' impostato a 0x16F084); successivi:
    mov_s r0,id + mov_s r1,r13 (a9 71) + jl_s (40 7e)."""
    ids = []
    i = 0
    while i + 4 <= len(data):
        if data[i + 1] == 0xD8:
            if (i + 6 <= len(data)
                    and data[i + 2:i + 6] == b'\xa9\x71\x40\x7e'):
                ids.append(data[i])
                i += 6
                continue
            if data[i + 2:i + 4] == b'\x40\x7e':
                ids.append(data[i])
                i += 4
                continue
        i += 2
    return ids


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'key_latch_targets_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, block_dir = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='key-latch-targets-16ed40-16f070',
                   limits=[
                       'Static decode + 11 CPU cases on ORIGINAL bytes '
                       '(pinned GNU ARC700 engine); no hardware',
                       'Windows .cb/.ed40/.f070/.f950/.epi/.kmach + query '
                       '0x16F920 and mode getter 0xCAD30 ORIGINALI',
                       '0x16ED40 I/O callees (0xCB5E4/0x12B0DC/0x32DE00/'
                       '0xAD920/0x12BD5C/0xCB5B0/0x1567F8) and callback '
                       'gates are STUBS: real I/O behavior NOT proven',
                       'ASSUNZIONE (a): 0xCB5B0 preserva r13, il verdetto '
                       'ok/fail e\' il ritorno di 0x12BD5C; alternativa '
                       '(b) 0xCB5B0-ritorna-r13 APERTA (tail 0xCA384)',
                       'Latch/records/mode RAM synthetic (dump gap); '
                       'V1.1 sample; NON_INSTALLARE'])
    try:
        lines = LISTING.read_text(errors='replace').splitlines()

        # --- 1. bl censuses ---------------------------------------------
        # 0x16ED40/0x16F070/0x16F950: census GLOBALE. I 7 callee interni
        # di 0x16ED40: solo i siti DENTRO la finestra 0x16ED40..0x16EDCC
        # (0x1567F8 e la 0xCB5B0/0xCB5E4 hanno centinaia di chiamanti).
        got = {}
        for ln in lines:
            m = CALL_RE.search(ln)
            if m:
                got.setdefault(int(m.group(3), 16), []).append(
                    int(m.group(1), 16))
        ED40_WIN = (0x16ED40, 0x16EDCC)
        for api, want in CENSUS.items():
            if api in (0x16ED40, 0x16F070, 0x16F950):
                got_in = list(got.get(api, []))
            else:
                got_in = [a for a in got.get(api, [])
                          if ED40_WIN[0] <= a < ED40_WIN[1]]
            assert sorted(got_in) == sorted(want), (
                hex(api), [hex(x) for x in sorted(got_in)])
        gen_sites = sorted(got.get(0x16F72C, []))
        assert len(gen_sites) == 19, [hex(x) for x in gen_sites]
        results['bl_census'] = {
            hex(k): [hex(x) for x in sorted(v)] for k, v in CENSUS.items()}

        # --- 2. pool words ----------------------------------------------
        for addr, value in POOL_WORDS.items():
            p = payload_of(blocks, addr)
            assert p is not None, hex(addr)
            w = struct.unpack_from('<I', payloads[p], addr - base[p])[0]
            assert w == value, (hex(addr), hex(w), hex(value))
        results['pool_words'] = {hex(a): hex(v)
                                 for a, v in POOL_WORDS.items()}

        # --- 3. strings ---------------------------------------------------
        for addr, s in STR_DUMP:
            p = payload_of(blocks, addr)
            d = payloads[p][addr - base[p]: addr - base[p] + len(s)]
            assert bytes(d) == s, (hex(addr), bytes(d))
        results['strings'] = {hex(a): s.decode('ascii')
                              for a, s in STR_DUMP}

        # --- 4. f070 id sequence (byte-level) ------------------------------
        p0 = payload_of(blocks, 0x16F070)
        body = payloads[p0][0x16F070 - base[p0]: 0x16F0E0 - base[p0]]
        ids = parse_f070_ids(body)
        assert ids == F070_IDS, [hex(x) for x in ids]
        results['f070_ids'] = [hex(x) for x in ids]

        # --- 5. dump at-rest latch cells -----------------------------------
        p1 = 1
        assert base[p1] == 0x360800
        d = payloads[p1]
        lat8 = d[0x3678A0 - base[p1]]
        lat9 = d[0x3678A1 - base[p1]]
        lat0 = d[0x367898 - base[p1]]
        c26 = d[0x36726B - base[p1]]
        assert (lat0, lat8, lat9, c26) == (1, 1, 0, 0), (
            lat0, lat8, lat9, c26)
        results['latch_at_rest'] = dict(latch0=lat0, latch8=lat8,
                                        latch9=lat9, cell_0x36726B=c26)

        # --- 6. LE scans ----------------------------------------------------
        def le_scan(val):
            hits = []
            needle = struct.pack('<I', val)
            for b in blocks:
                data = payloads[b['index']]
                start = 0
                while True:
                    i = data.find(needle, start)
                    if i < 0:
                        break
                    hits.append((b['index'], base[b['index']] + i))
                    start = i + 1
            return hits
        assert sorted(le_scan(0x16F950)) == sorted(LE_16F950)
        assert le_scan(0x16ED40) == []
        assert le_scan(0x16F070) == []
        results['le_scans'] = dict(
            f950=[(p, hex(a)) for p, a in le_scan(0x16F950)],
            ed40=[], f070=[])

        # --- 7. CPU cases --------------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='key-latch-targets'))
        r.prepare()
        r.results.update(static_pass=results)
        cases = []
        for idx, spec in enumerate(CPU_SPECS):
            name = spec['name']
            stubs = [STUB_LIB[s] for s in spec['stubs']]
            asm = (harness(spec['extra'])
                   + ''.join(g() for (_, _, g) in stubs)
                   + probe(spec['asserts'], spec['success'], idx))
            s = out / f'{name}.s'
            s.write_text(asm)
            obj = out / f'{name}.o'
            assert r.command(f'{name}_as', [
                TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                '-o', obj, s]).returncode == 0
            bin_objs = []
            for (pidxw, wlo, whi, section) in spec['windows']:
                assert payload_of(blocks, wlo) == pidxw, (hex(wlo), pidxw)
                data = payloads[pidxw][wlo - base[pidxw]:
                                       whi - base[pidxw]]
                orig = out / f'{name}_{section}.bin'
                orig.write_bytes(data)
                sha_check = hashlib.sha256(data).hexdigest()
                bo = out / f'{name}_{section}_bin.o'
                assert r.command(f'{name}_{section}_oc', [
                    TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary',
                    '-O', 'elf32-littlearc', '-B', 'arc',
                    '--rename-section',
                    f'.data={section},alloc,load,readonly,code,contents',
                    '--change-section-vma', f'.data={hex(wlo)}',
                    '--strip-all', orig, bo]).returncode == 0
                bin_objs.append(bo)
                results.setdefault('window_sha256', {})[section] = sha_check
            elf = out / f'{name}.elf'
            ld = out / f'{name}.ld'
            ld.write_text(
                'ENTRY(_start)\nSECTIONS {\n'
                '  .text 0x1000 : { *(.text .text.*) }\n'
                + ''.join(f'  {section} {hex(wlo)} : {{ *({section}) }}\n'
                          for (_, wlo, _, section) in spec['windows'])
                + ''.join(f'  {sec} {hex(addr)} : {{ *({sec}) }}\n'
                          for (sec, addr, _) in stubs)
                + ''.join(f'  {sec} {hex(addr)} : {{ *({sec}) }}\n'
                          for (sec, addr, _) in RAM_SECTIONS)
                + f'  .probe {hex(PROBE_AT)} : {{ *(.probe) }}\n'
                  f'  .log {hex(LOG)} : {{ *(.log) }}\n'
                  '  .stack 0xC8F000 (NOLOAD) : { *(.stack .stack.*) }\n'
                  '} \n')
            cmd = [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-T', ld, '-o', elf,
                   obj] + bin_objs
            assert r.command(f'{name}_ld', cmd).returncode == 0
            ep, segments = elf_loads(elf)
            assert ep == 0x1000, hex(ep)
            for (pidxw, wlo, whi, section) in spec['windows']:
                want = payloads[pidxw][wlo - base[pidxw]: whi - base[pidxw]]
                by = [seg for seg in segments
                      if seg['address'] <= wlo
                      and wlo + (whi - wlo) <= seg['address'] + seg['size']]
                assert len(by) == 1, (hex(wlo), segments)
                data = by[0]['data'][wlo - by[0]['address']:]
                assert data[:whi - wlo] == bytes(want), hex(wlo)
            case, sim_text = r.run(name, '/result/' + f'{name}.elf')
            assert case['exit_code'] == 11, (name, case)
            fault = case['fault']
            assert fault is not None and fault['operation'] == 'read', (
                name, fault)
            assert int(fault['address'], 16) == spec['success'], (
                name, fault, hex(spec['success']))
            cases.append(dict(name=name, success=hex(spec['success']),
                              instructions=case['instructions'],
                              fault=fault, original_bytes=True))
            print(f'PASS {name} -> {hex(spec["success"])}', flush=True)
        assert len(cases) == 10, len(cases)
        results['cpu_cases'] = cases
        results['status'] = 'PASS'
        results['verdict'] = 'PASS_KEY_LATCH_TARGETS_16ED40_16F070_CPU'
        print('PASS_KEY_LATCH_TARGETS_16ED40_16F070_CPU', stamp)
    except AssertionError as exc:
        results['status'] = 'FAIL'
        results['error'] = repr(exc)
        print('FAIL:', exc, flush=True)
        raise
    finally:
        out.mkdir(parents=True, exist_ok=True)
        (out / 'verified_evidence.json').write_text(
            json.dumps(results, indent=2, default=str) + '\n')
        if results['status'] == 'PASS':
            latest = (ROOT / 'Risultati/GUI_S33'
                      / 'key_latch_targets_latest.json')
            latest.write_text(json.dumps(results, indent=2, default=str)
                              + '\n')
        print('Evidence:', out / 'verified_evidence.json')


if __name__ == '__main__':
    main()
