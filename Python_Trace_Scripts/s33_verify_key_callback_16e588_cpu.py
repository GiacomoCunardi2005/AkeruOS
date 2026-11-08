#!/usr/bin/env python3
"""CALLBACK 0x16E588 DELLA MACCHINA TASTI (it.52, punto it.51(a)):
decodifica statica + 17 casi CPU su byte ORIGINALI (motore pinnato GNU
ARC700). E' il ponte macchina tasti -> callback -> notifica/post -> code.

Scoperta centrale (statica, verificata qui in CPU):
- 0x16E588 (pool 0x16E38C, registrata all'init 0x16E2F4 via 0x16F988 nella
  tabella callback 0x446A08; ZERO bl chiamanti: callback pura) riceve dal
  fan-out 0x16F6B0 (classe, stato, &evento) con evento halfword letta da
  [r2] con ldw_s.x (segno esteso).
- LATCH ctx 0x367898 (pool 0x16E6D8): byte[+8]=latch8, byte[+9]=latch9,
  cella esterna byte[0x36726B] (pool 0x16E6DC). NEL DUMP A RIPOSO
  latch8=1, latch9=0, byte[0x36726B]=0, word[0x367898]=1.
- Ingresso: latch8==0 -> corpo principale. latch8!=0:
  byte[0x36726B]!=0 ed evento==0x2701 -> 0x16ED40 + latch8:=0, return 0.
  Altrimenti latch9==0: se query(0x4E)!=0 ed evento==0x481 -> latch9:=1
  (poi corpo principale). latch9!=0: se evento in [0x80,0x307F] e classe
  non in {0x4E,9} -> latch9:=0 (poi corpo); se latch9 resta != 0 e
  query(9)!=0 ed evento==0x2701 -> 0x16ED40 + latch8:=0 + latch9:=0,
  return 0.
- Corpo principale: gate 0xC9BF8()!=1 oppure 0x16BC90()!=0 ->
  0xC68F0() e return 1 (il fan-out inserisce allora l'evento nell'anello
  0x17BC7C: percorso RAW di it.51). Modo (getter ORIGINALE 0xCAD30,
  byte 0xC8E80C via pool 0xCAAC4)==0x15 e 0xD0CA4()==1 e
  0<evento<=0x3FFF e slot=(evento&0x3F80)>>7==0x62, cioe' evento in
  [0x3100,0x317F] (solo 0x3100 e' prodotto dalla mappa tasti) -> post
  (0, 0x4002, 1) via 0x169EB4, return 0. Classe in
  {0x64,6,5,0xE,0xB,0xF} -> return 0 SENZA post (0xE = classe 14 =
  pulsante 0x700/0x701, SLOT AKERUOS 2; 0xB = classe 11 = pulsante
  0x580/0x581, SLOT AKERUOS 1; 0x64 = classe 0x3200 repeat: la
  callback NON converte questi tasti in notifiche). Evento 0x3100 ->
  0x16F070(1), return 0. Altrimenti: post (0, 0x4006, classe),
  0xC68F0(), gate 0xCB618()!=0 ed evento!=0x3101 -> repost
  (0, evento, stato). Sempre return 0 dal corpo.
- NOTA FAN-OUT (revisione cb588-review-52): return 1 NON basta per
  l'anello: 0x16F6B0 inserisce (0,evento,r19,1) in 0x17BC7C solo se
  byte[0x3678F9]!=0 (a riposo 1), arg r4!=0 e bit0 di
  halfword[0x446808+4*classe+2] (0x16F6A4, settabile via 0x16F950);
  return 0 di UN callback ferma la catena (short-circuit) e r0 e' il
  verdetto dell'ULTIMO callback invocato: "return 1 -> anello" e'
  condizionato. 0x16F988 registra nella PRIMA CELLA LIBERA della
  tabella 10 (0x16F9C8..0x16F9DE): indice runtime, non fisso.
- CLASSI PROTETTE DAL LATCH: il blocco latch9 NON cancella il latch
  per classe in {0x4E, 9} (0x4E = 78 = classe del pulsante 0x2700/0x2701,
  SLOT AKERUOS 4) ne' per eventi fuori [0x80,0x307F].
- SIGNIFICATO GUI: ogni tasto fisico arriva anche come notifica di
  servizio 0x4006 con ARG=CLASSE (reattore 0x20F414, it.21) e,
  se il gate 0xCB618 lo consente, come evento vero nella coda 0x169EB4.
- CENSIMENTI (congelati): bl 0x16E588 = 0; bl 0x16ED40 = {0x16E5B8,
  0x16E616} (solo dentro la callback); bl 0x16F070 = {0x16E692,
  0x16ECEC, 0x16EE26}; bl 0x169EB4 dentro la finestra callback =
  {0x16E668, 0x16E6A0, 0x16E6BE}; 19 siti generatore 0x16F72C (it.51)
  con classe costante 1/2/0xC/0x62/0x65/0x66/0x77 (eventi virtuali
  0x80/0x100/0x600/0x3100/0x3280/0x3300/0x3B80 e complementi |1) e idx
  0xFF, piu' il sito dinamico 0x16EC28 (classe dinamica, idx 0xFF),
  il sito fisico 0x16F8D4 (scanner, idx reale del descrittore) e
  0x144A82 (classe 0x77 dopo switch 0xD18FC).

CPU (17 casi, byte originali 0x16E588..0x16E6E0 + query 0x16F920 e
getter modo 0xCAD30 ORIGINALI): stub con log per 0xC9BF8/0x16BC90/
0xD0CA4/0xC68F0/0xCB618 (ritorno da cella), 0x169EB4 (log post),
0x16ED40, 0x16F070. RAM sintetiche: latch 0x367898/0x36726B, celle
mode 0xC8E80C, record tasti 0x446808 (gap del dump). NESSUN hardware;
NON_INSTALLARE.
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
CNT_C9BF8 = LOG + 0x30
CNT_BC90 = LOG + 0x34
CNT_D0CA4 = LOG + 0x38
CNT_C68F0 = LOG + 0x3C
CNT_CB618 = LOG + 0x40
CNT_ED40 = LOG + 0x44
CNT_F070 = LOG + 0x48
ED40_R = LOG + 0x50          # r0,r1,r2
F070_R = LOG + 0x60          # r0,r1
POST_COUNT = LOG + 0x80
POST_ENT = LOG + 0x90         # = POST_COUNT+16 (stub), 16 byte per voce

LATCH8 = 0x3678A0
LATCH9 = 0x3678A1
CELL26B = 0x36726B
MODECELL = 0xC8E80C

W_MILI = (0, 0x334100, 0x3341E4, '.mili')
W_CB = (0, 0x16E588, 0x16E6E0, '.cb')
W_KMACH = (0, 0x16F630, 0x16FA60, '.kmach')
W_MODEGET = (0, 0xCAD30, 0xCAD38, '.modeget')
W_MODEPOOL = (0, 0xCAAC0, 0xCAAD0, '.modepool')

POOL_WORDS = {0x16E6D8: 0x367898, 0x16E6DC: 0x36726B,
              0xCAAC4: 0xC8E80C, 0x16FA34: 0x446808}

CENSUS = {
    0x16E588: [],
    0x16ED40: [0x16E5B8, 0x16E616],
    0x16F070: [0x16E692, 0x16ECEC, 0x16EE26],
}
POST_SITES_IN_CB = [0x16E668, 0x16E6A0, 0x16E6BE]
GEN_SITES = {  # sito -> classe costante (None = dinamica/fisica)
    0x144A82: 0x77, 0x16E8A6: 1, 0x16E8CA: 2, 0x16E8F6: 0x77,
    0x16E9D8: 1, 0x16EA2A: 2, 0x16EA7A: 1, 0x16EA94: 1,
    0x16EAD4: 2, 0x16EC28: None, 0x16ECA2: 0xC, 0x16EDFE: 0x62,
    0x16EF64: 0x66, 0x16EF7A: 0x65, 0x16EFC8: 0x65,
    0x16EFEC: 0x77, 0x16F00E: 0x65, 0x16F176: 0x77, 0x16F8D4: None,
}
LE_EXPECT = {0x16E588: [(0, 0x16E38C)]}


def post_entry(k, r0, r1, r2):
    return [(POST_ENT + 16 * k + 0, 4, r0),
            (POST_ENT + 16 * k + 4, 4, r1),
            (POST_ENT + 16 * k + 8, 4, r2)]


def zero_counts():
    return [(CNT_C9BF8, 4, 0), (CNT_BC90, 4, 0), (CNT_D0CA4, 4, 0),
            (CNT_C68F0, 4, 0), (CNT_CB618, 4, 0), (CNT_ED40, 4, 0),
            (CNT_F070, 4, 0), (POST_COUNT, 4, 0)]


def presets(mode=0x2C, ret_c9bf8=1, ret_bc90=0, ret_d0ca4=0,
            ret_cb618=0, latch8=0, latch9=0, cell26b=0,
            recs=()):
    t = [f' mov r0,{hex(mode)}\n mov r1,{hex(MODECELL)}\n stb r0,[r1,0]\n',
         f' mov r0,{hex(ret_c9bf8)}\n mov r1,{hex(RET_C9BF8)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(ret_bc90)}\n mov r1,{hex(RET_BC90)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(ret_d0ca4)}\n mov r1,{hex(RET_D0CA4)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(ret_cb618)}\n mov r1,{hex(RET_CB618)}\n st r0,[r1,0]\n',
         f' mov r0,{hex(latch8)}\n mov r1,{hex(LATCH8)}\n stb r0,[r1,0]\n',
         f' mov r0,{hex(latch9)}\n mov r1,{hex(LATCH9)}\n stb r0,[r1,0]\n',
         f' mov r0,{hex(cell26b)}\n mov r1,{hex(CELL26B)}\n stb r0,[r1,0]\n']
    for classe, stato in recs:
        t.append(f' mov r0,{hex(stato)}\n'
                 f' mov r1,{hex(0x446808 + 4 * classe)}\n stb r0,[r1,0]\n')
    return ''.join(t)


def call_cb(classe, stato, event):
    return (f' mov r0,{hex(event)}\n mov r1,{hex(EVADDR)}\n sth r0,[r1,0]\n'
            f' mov r0,{hex(classe)}\n mov r1,{hex(stato)}\n'
            f' mov r2,{hex(EVADDR)}\n mov r12,0x16e588\n jl_s [r12]\n'
            f' mov r1,{hex(RETVAL)}\n st r0,[r1,0]\n')


MAIN = presets()   # modo 0x2C, gate aperti, latch azzerati

CPU_SPECS = [
    dict(name='gate_c9bf8_fail',
         extra=presets(ret_c9bf8=0) + call_cb(14, 1, 0x700),
         asserts=[(RETVAL, 4, 1), (CNT_C9BF8, 4, 1), (CNT_C68F0, 4, 1),
                  (CNT_BC90, 4, 0), (CNT_D0CA4, 4, 0), (CNT_CB618, 4, 0),
                  (CNT_ED40, 4, 0), (CNT_F070, 4, 0), (POST_COUNT, 4, 0),
                  (LATCH8, 1, 0), (LATCH9, 1, 0)],
         success=0xDEADB001),
    dict(name='gate_bc90_fail',
         extra=presets(ret_bc90=1) + call_cb(14, 1, 0x700),
         asserts=[(RETVAL, 4, 1), (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1),
                  (CNT_C68F0, 4, 1), (CNT_D0CA4, 4, 0), (CNT_CB618, 4, 0),
                  (CNT_ED40, 4, 0), (CNT_F070, 4, 0), (POST_COUNT, 4, 0)],
         success=0xDEADB002),
    dict(name='main_post_repost',
         extra=presets(ret_cb618=1) + call_cb(78, 1, 0x2700),
         asserts=[(RETVAL, 4, 0), (POST_COUNT, 4, 2),
                  (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1), (CNT_C68F0, 4, 1),
                  (CNT_CB618, 4, 1), (CNT_D0CA4, 4, 0),
                  (CNT_ED40, 4, 0), (CNT_F070, 4, 0)]
         + post_entry(0, 0, 0x4006, 78) + post_entry(1, 0, 0x2700, 1),
         success=0xDEADB003),
    dict(name='main_post_cb618_zero',
         extra=MAIN + call_cb(78, 1, 0x2700),
         asserts=[(RETVAL, 4, 0), (POST_COUNT, 4, 1),
                  (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1), (CNT_C68F0, 4, 1),
                  (CNT_CB618, 4, 1), (CNT_D0CA4, 4, 0)]
         + post_entry(0, 0, 0x4006, 78),
         success=0xDEADB004),
    dict(name='main_post_3101_norepost',
         extra=MAIN + presets(ret_cb618=1) + call_cb(98, 0, 0x3101),
         asserts=[(RETVAL, 4, 0), (POST_COUNT, 4, 1),
                  (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1), (CNT_C68F0, 4, 1),
                  (CNT_CB618, 4, 1), (CNT_D0CA4, 4, 0)]
         + post_entry(0, 0, 0x4006, 98),
         success=0xDEADB005),
    dict(name='swallow_class_0x64',
         extra=MAIN + presets(ret_cb618=1) + call_cb(0x64, 1, 0x3200),
         asserts=[(RETVAL, 4, 0), (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1),
                  (CNT_D0CA4, 4, 0), (CNT_C68F0, 4, 0), (CNT_CB618, 4, 0),
                  (CNT_ED40, 4, 0), (CNT_F070, 4, 0), (POST_COUNT, 4, 0),
                  (LATCH8, 1, 0)],
         success=0xDEADB006),
    dict(name='swallow_class_0xe_700',
         extra=MAIN + presets(ret_cb618=1) + call_cb(14, 1, 0x700),
         asserts=[(RETVAL, 4, 0), (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1),
                  (CNT_D0CA4, 4, 0), (CNT_C68F0, 4, 0), (CNT_CB618, 4, 0),
                  (CNT_ED40, 4, 0), (CNT_F070, 4, 0), (POST_COUNT, 4, 0),
                  (LATCH8, 1, 0)],
         success=0xDEADB010),
    dict(name='swallow_class_0xb_580',
         extra=MAIN + presets(ret_cb618=1) + call_cb(11, 1, 0x580),
         asserts=[(RETVAL, 4, 0), (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1),
                  (CNT_D0CA4, 4, 0), (CNT_C68F0, 4, 0), (CNT_CB618, 4, 0),
                  (CNT_ED40, 4, 0), (CNT_F070, 4, 0), (POST_COUNT, 4, 0),
                  (LATCH8, 1, 0)],
         success=0xDEADB011),
    dict(name='event_3100_f070',
         extra=MAIN + call_cb(98, 1, 0x3100),
         asserts=[(RETVAL, 4, 0), (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1),
                  (CNT_F070, 4, 1), (F070_R, 4, 1),
                  (CNT_C68F0, 4, 0), (CNT_CB618, 4, 0),
                  (POST_COUNT, 4, 0), (CNT_ED40, 4, 0)],
         success=0xDEADB007),
    dict(name='mode15_3100_post4006_arg1',
         extra=presets(mode=0x15, ret_d0ca4=1) + call_cb(98, 1, 0x3100),
         asserts=[(RETVAL, 4, 0), (POST_COUNT, 4, 1),
                  (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1), (CNT_D0CA4, 4, 1),
                  (CNT_C68F0, 4, 0), (CNT_CB618, 4, 0), (CNT_F070, 4, 0)]
         + post_entry(0, 0, 0x4002, 1),
         success=0xDEADB008),
    dict(name='mode15_d0ca4_fail_f070',
         extra=presets(mode=0x15, ret_d0ca4=0) + call_cb(98, 1, 0x3100),
         asserts=[(RETVAL, 4, 0), (CNT_C9BF8, 4, 1), (CNT_BC90, 4, 1),
                  (CNT_D0CA4, 4, 1), (CNT_F070, 4, 1), (F070_R, 4, 1),
                  (CNT_C68F0, 4, 0), (POST_COUNT, 4, 0)],
         success=0xDEADB009),
    dict(name='latch8_2701_ed40',
         extra=presets(latch8=1, cell26b=1) + call_cb(78, 0, 0x2701),
         asserts=[(RETVAL, 4, 0), (CNT_ED40, 4, 1), (LATCH8, 1, 0),
                  (LATCH9, 1, 0), (POST_COUNT, 4, 0), (CNT_C9BF8, 4, 0),
                  (CNT_C68F0, 4, 0), (CNT_F070, 4, 0)],
         success=0xDEADB00A),
    dict(name='latch9_set_on_481',
         extra=presets(latch8=1, recs=((0x4E, 1),)) + call_cb(9, 0, 0x481),
         asserts=[(RETVAL, 4, 0), (LATCH9, 1, 1), (LATCH8, 1, 1),
                  (POST_COUNT, 4, 1), (CNT_C9BF8, 4, 1),
                  (CNT_C68F0, 4, 1), (CNT_CB618, 4, 1), (CNT_ED40, 4, 0)]
         + post_entry(0, 0, 0x4006, 9),
         success=0xDEADB00B),
    dict(name='latch9_clear_normal',
         extra=presets(latch8=1, latch9=1, ret_cb618=1)
         + call_cb(67, 1, 0x2180),
         asserts=[(RETVAL, 4, 0), (LATCH9, 1, 0), (LATCH8, 1, 1),
                  (POST_COUNT, 4, 2), (CNT_ED40, 4, 0)]
         + post_entry(0, 0, 0x4006, 67) + post_entry(1, 0, 0x2180, 1),
         success=0xDEADB00C),
    dict(name='latch9_query9_2701_ed40',
         extra=presets(latch8=1, latch9=1, recs=((9, 1),))
         + call_cb(9, 0, 0x2701),
         asserts=[(RETVAL, 4, 0), (CNT_ED40, 4, 1), (LATCH8, 1, 0),
                  (LATCH9, 1, 0), (POST_COUNT, 4, 0), (CNT_C68F0, 4, 0),
                  (CNT_C9BF8, 4, 0)],
         success=0xDEADB00D),
    dict(name='latch9_query9_zero_main',
         extra=presets(latch8=1, latch9=1) + call_cb(9, 1, 0x480),
         asserts=[(RETVAL, 4, 0), (LATCH9, 1, 1), (LATCH8, 1, 1),
                  (POST_COUNT, 4, 1), (CNT_CB618, 4, 1), (CNT_ED40, 4, 0)]
         + post_entry(0, 0, 0x4006, 9),
         success=0xDEADB00E),
    dict(name='latch8_zero_skips_latch9',
         extra=presets(latch9=1, recs=((0x4E, 1),)) + call_cb(9, 0, 0x481),
         asserts=[(RETVAL, 4, 0), (LATCH9, 1, 1), (LATCH8, 1, 0),
                  (POST_COUNT, 4, 1), (CNT_C9BF8, 4, 1),
                  (CNT_C68F0, 4, 1), (CNT_CB618, 4, 1)]
         + post_entry(0, 0, 0x4006, 9),
         success=0xDEADB00F),
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


def stub_count(sec, count_cell, fields_base=0, ret_cell=None):
    body = (f' push_s blink\n mov r3,{hex(count_cell)}\n'
            ' ld r4,[r3,0]\n add r5,r4,1\n st r5,[r3,0]\n')
    if fields_base:
        body += (f' mov r3,{hex(fields_base)}\n'
                 ' st r0,[r3,0]\n st r1,[r3,4]\n'
                 ' st r2,[r3,8]\n')
    if ret_cell is not None:
        body += (f' mov r3,{hex(ret_cell)}\n ld r0,[r3,0]\n')
    else:
        body += ' mov r0,0\n'
    return (f'.section {sec},"ax",@progbits\n .org 0\n' + body +
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


STUB_SECTIONS = [
    ('.s_c9bf8', 0xC9BF8, lambda: stub_ret('.s_c9bf8', CNT_C9BF8, RET_C9BF8)),
    ('.s_bc90', 0x16BC90, lambda: stub_ret('.s_bc90', CNT_BC90, RET_BC90)),
    ('.s_d0ca4', 0xD0CA4, lambda: stub_ret('.s_d0ca4', CNT_D0CA4, RET_D0CA4)),
    ('.s_cb618', 0xCB618, lambda: stub_ret('.s_cb618', CNT_CB618, RET_CB618)),
    ('.s_c68f0', 0xC68F0, lambda: stub_count('.s_c68f0', CNT_C68F0)),
    ('.s_ed40', 0x16ED40,
     lambda: stub_count('.s_ed40', CNT_ED40, fields_base=ED40_R)),
    ('.s_f070', 0x16F070,
     lambda: stub_count('.s_f070', CNT_F070, fields_base=F070_R)),
    ('.s_post', 0x169EB4, stub_post),
]
RAM_SECTIONS = [
    ('.kmram', 0x446800, 0x240),
    ('.latram', 0x367890, 0x20),
    ('.l26b', 0x367260, 0x18),
    ('.modecell', 0xC8E808, 0x8),
]


# ------------------------------------------------------------- static ----
CALL_RE = re.compile(r'V([0-9A-F]{6,8}) \| [0-9a-f ]+\| '
                     r'(bl|bl\.d|bl_s|bl_s\.d)\s+?-?\d+\s+'
                     r';0x(16e588|16ed40|16f070|169eb4|16f72c)\b')


def payload_of(blocks, addr):
    for b in blocks:
        if b['load_address_candidate'] <= addr \
                < b['load_address_candidate'] + b['size']:
            return b['index']
    return None


def main():
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out = ROOT / 'Risultati/GUI_S33' / f'key_callback_16e588_cpu_{stamp}'
    print('Prove:', out, flush=True)
    blocks, payloads, block_dir = verified_payloads(ROOT)
    base = {b['index']: b['load_address_candidate'] for b in blocks}
    results = dict(status='RUNNING', utc=stamp,
                   action='key-callback-16e588',
                   limits=[
                       'Static decode + 17 CPU cases on ORIGINAL bytes '
                       '(pinned GNU ARC700 engine); no hardware',
                       'Callback window 0x16E588..0x16E6E0, query 0x16F920 '
                       'and mode getter 0xCAD30 ORIGINALI',
                       'Gate functions 0xC9BF8/0x16BC90/0xD0CA4/0xC68F0/'
                       '0xCB618 and post 0x169EB4, 0x16ED40, 0x16F070 are '
                       'STUBS with logging: real behavior NOT proven here',
                       'Latch RAM 0x367898/0x36726B, mode cell 0xC8E80C and '
                       'key records 0x446808 are SYNTHETIC fixtures in the '
                       'CPU cases (dump at-rest values asserted statically)',
                       'Fan-out/ring path (callback return 1 -> anello '
                       '0x17BC7C) is NOT run here: proven in it.51',
                       'V1.1 sample; NON_INSTALLARE'])
    try:
        lines = LISTING.read_text(errors='replace').splitlines()

        # --- 1. bl censuses ---------------------------------------------
        got = {}
        for ln in lines:
            m = CALL_RE.search(ln)
            if m:
                got.setdefault(int(m.group(3), 16), []).append(
                    int(m.group(1), 16))
        for api, want in CENSUS.items():
            assert sorted(got.get(api, [])) == sorted(want), (
                hex(api), [hex(x) for x in sorted(got.get(api, []))])
        gen_sites = sorted(got.get(0x16F72C, []))
        assert gen_sites == sorted(GEN_SITES), (
            [hex(x) for x in gen_sites])
        # post sites inside the callback window
        post_in = sorted(a for a in got.get(0x169EB4, [])
                         if 0x16E588 <= a < 0x16E6E0)
        assert post_in == sorted(POST_SITES_IN_CB), post_in
        results['bl_census'] = {
            hex(k): [hex(x) for x in sorted(v)] for k, v in CENSUS.items()}
        results['post_sites_in_callback'] = [hex(x) for x in post_in]
        results['generator_sites'] = {
            hex(s): (hex(c) if c else 'dynamic') for s, c
            in sorted(GEN_SITES.items())}

        # --- 2. constant-class loads near each generator site --------------
        addr_line = []
        for ln in lines:
            m = re.search(r' V([0-9A-F]{6,8}) \|', ln)
            if m:
                addr_line.append((int(m.group(1), 16), ln))
        for site, classe in GEN_SITES.items():
            near = [ln for (a, ln) in addr_line if site - 0x18 <= a <= site]
            if classe is None:
                continue
            pat = re.compile(rf'mov_s\tr1,0x{classe:x}\b')
            assert any(pat.search(ln) for ln in near), (
                hex(site), hex(classe))
        idx_ff = 0
        for site in GEN_SITES:
            near = [ln for (a, ln) in addr_line if site - 0x18 <= a <= site]
            pat = re.compile(r'mov_s\tr0,0xff\b')
            idx_ff += any(pat.search(ln) for ln in near)
        assert idx_ff == len(GEN_SITES) - 1, idx_ff  # solo 0x16F8D4 no
        results['generator_site_idx_ff'] = idx_ff

        # --- 3. pool words ----------------------------------------------
        for addr, value in POOL_WORDS.items():
            p = payload_of(blocks, addr)
            assert p is not None, hex(addr)
            w = struct.unpack_from('<I', payloads[p], addr - base[p])[0]
            assert w == value, (hex(addr), hex(w), hex(value))
        results['pool_words'] = {hex(a): hex(v)
                                 for a, v in POOL_WORDS.items()}

        # --- 4. dump at-rest latch cells ---------------------------------
        p1 = 1
        assert base[p1] == 0x360800
        d = payloads[p1]
        lat8 = d[0x3678A0 - base[p1]]
        lat9 = d[0x3678A1 - base[p1]]
        c26 = d[0x36726B - base[p1]]
        w98 = struct.unpack_from('<I', d, 0x367898 - base[p1])[0]
        assert (lat8, lat9, c26, w98) == (1, 0, 0, 1), (
            lat8, lat9, c26, w98)
        results['latch_at_rest'] = dict(latch8=lat8, latch9=lat9,
                                        cell_0x36726B=c26,
                                        word_0x367898=w98)

        # --- 5. LE scans --------------------------------------------------
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
        for val, want in LE_EXPECT.items():
            assert sorted(le_scan(val)) == sorted(want), (
                hex(val), [hex(h[1]) for h in le_scan(val)])
        results['le_scans'] = {hex(v): [(p, hex(a)) for p, a in e]
                               for v, e in LE_EXPECT.items()}

        # --- 6. CPU cases --------------------------------------------------
        r = Runner(SimpleNamespace(legacy_root=LEGACY, toolchain=TOOLCHAIN,
                                   output=out, action='key-cb-16e588'))
        r.prepare()
        r.results.update(static_pass=results)
        cases = []
        for idx, spec in enumerate(CPU_SPECS):
            name = spec['name']
            windows = spec.get('windows', [W_CB, W_KMACH, W_MODEGET,
                                           W_MODEPOOL]) + [W_MILI]
            asm = (harness(spec['extra'])
                   + ''.join(gen() for (_, _, gen) in STUB_SECTIONS)
                   + probe(spec['asserts'], spec['success'], idx))
            s = out / f'{name}.s'
            s.write_text(asm)
            obj = out / f'{name}.o'
            assert r.command(f'{name}_as', [
                TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL',
                '-o', obj, s]).returncode == 0
            bin_objs = []
            for (pidxw, wlo, whi, section) in windows:
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
                          for (_, wlo, _, section) in windows)
                + ''.join(f'  {sec} {hex(addr)} : {{ *({sec}) }}\n'
                          for (sec, addr, _) in STUB_SECTIONS)
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
            for (pidxw, wlo, whi, section) in windows:
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
        assert len(cases) == 17, len(cases)
        results['cpu_cases'] = cases
        results['status'] = 'PASS'
        results['verdict'] = 'PASS_KEY_CALLBACK_16E588_CPU'
        print('PASS_KEY_CALLBACK_16E588_CPU', stamp)
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
                      / 'key_callback_16e588_latest.json')
            latest.write_text(json.dumps(results, indent=2, default=str)
                              + '\n')
        print('Evidence:', out / 'verified_evidence.json')


if __name__ == '__main__':
    main()
