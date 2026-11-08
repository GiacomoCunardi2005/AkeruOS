#!/usr/bin/env python3
"""Integrazione con il manager Nikon: apertura 0x1453E4(id)->0x145180, messaggi via post 0x17BC7C e corpo di WindowMgr.
Base: profilo da dump hardware.
Oggetto finestra Nikon = flag (bit0=0) a +0, procedura a +0xC; il dispatcher originale 0x169E1C la chiama.
Il disegno usa il percorso testo Nikon originale 0x186D08. Nessun hardware; dump originale intatto."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, os, re, struct, subprocess, sys
SIM_TIMEOUT = int(os.environ.get('S33_SIM_TIMEOUT', '60'))  # secondi di simulazione per fase
sys.path.insert(0, str(Path(__file__).resolve().parent))
from s33_run_gnu_arc700 import ROOT, TOOLCHAIN, IMAGE, sha
# motore v8: v7 + AUX 0x48 (DC_CTRL) a riposo 0, per il polling del flush cache (0x17FAEA)
# S33_ONLY=5291c (motore v13): i segnalatori valgono solo quando il task corrente e' il probe (TCB 0x5291C); le attese degli altri task (Live View) restano bloccanti.
# Segnalatore modellato (motore v10): S33_POKE_ALL=1 imposta a ogni istruzione tutti i bit dei flag di ogni event group 'nvel' del dump,
# come se un altro task/interrupt li segnalasse sempre. Ipotesi di modello, non uno scheduler.
POKE_ALL = os.environ.get('S33_POKE_ALL') == '1'
REAL_KEYS = os.environ.get('S33_REAL_KEYS') == '1'   # tasti coerenti: 0x700 avanza (+ rilascio 0x701 ignorato), 0x2180 chiude (+ rilascio 0x2181 ignorato)
NIKON_CLEAR = os.environ.get('S33_NIKON_CLEAR') == '1'   # cancella il rettangolo del menu con la routine Nikon 0x17B104 (riempie i due buffer OSD) invece di scrivere nel piano
RELEASE_SD = os.environ.get('S33_RELEASE_SD') == '1'   # il probe (che prosegue il task MEMDUMP) rilascia il semaforo del volume SD B 0x1A0000D tenuto dal dumper
FIX_KLISTS = os.environ.get('S33_FIX_KLISTS') == '1'   # ripara nella COPIA DI LAVORO le liste kernel lasciate a meta' dal dump non atomico (vedi fix_kernel_lists)
SCHEDTICK = os.environ.get('S33_SCHEDTICK') == '1'   # motore v17: ai salti verso lo scheduler 0xB2D50 lo stub sched_tick emette i tick TIMER0 maturati (1 istruzione = 1 conteggio a 200 MHz, ipotesi di modello)
TICK = os.environ.get('S33_TICK') == '1'   # motore v14: il `sleep 0` dello scheduler inattivo esegue il gestore TIMER0 originale (stub tick_stub)
POKE = None
FULL = os.environ.get('S33_FORCE_FULL') == '1'  # percorso completo del motore (--trace-insn, righe di traccia scartate): serve ai segnalatori, l'hook non gira nel percorso veloce
LAB = ROOT / ('work/gnu_arc700_dsp_lab_v17_timetick' if SCHEDTICK else 'work/gnu_arc700_dsp_lab_v14_sleepvec' if TICK else 'work/gnu_arc700_dsp_lab_v13_curtask' if POKE_ALL else 'work/gnu_arc700_dsp_lab_v8_dcctrl')
BUILD = ROOT / ('outputs/gnu_arc700_dsp/build_v17_timetick' if SCHEDTICK else 'outputs/gnu_arc700_dsp/build_v14_sleepvec' if TICK else 'outputs/gnu_arc700_dsp/build_v13_curtask' if POKE_ALL else 'outputs/gnu_arc700_dsp/build_v8_dcctrl') / 'verified_evidence.json'

DUMP = ROOT / 'Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN'
DUMP_SHA = 'c91888b23a8def81dc0afbf5a62a6210361308fea030bfbafcf6a43338286107'
BASE, CODE, RES, STACK_BASE = 0x100, 0x1041000, 0x3000000, 0x1048000
STACK_TOP = STACK_BASE + 16384
HI_BASE, HI_SIZE = 0x0F680000, 0x40000
TABLE, COUNT, QCTL = 0x3F5900, 197, 0x367BBC
# registri MMIO dichiarati (lettura = 0): vengono aggiunti solo quando il codice originale li legge e il simulatore si ferma
MMIO = [0x0FE80070, 0xfef000c, 0xfed4144, 0xfef0004, 0xfed2018, 0xfed2024, 0xfed2020, 0xfed201c, 0xfe8009c, 0xfec8280, 0xfec1028, 0xfec102c, 0xff130dc, 0xff10240, 0xff130d8, 0xfee01c0, 0xff10280, 0xfee0200, 0xff13000, 0xff101a0, 0xff10000, 0xff10348, 0xff10004, 0xff10008, 0xff1000c, 0xff10010, 0xff101a4, 0xff101a8, 0xff101ac, 0xff101b0, 0xff10340, 0xfef0028, 0xff1016c, 0xff10014, 0xfec8000, 0xff1015c, 0xff10160, 0xff10164, 0xff10168, 0xff1309c, 0xff130a0, 0xff130a4, 0xff130a8, 0xff13018, 0xff1301c, 0xff13020, 0xff13024, 0xff13028, 0xff1302c, 0xff1322c, 0xff13030]
# registri con valore modellato (file mappati): 0x0FF63004 bit 4 = periferica pronta (attesa a 0x19CDC4)
# 0x0FE7020C: flag di pronto del controller tasti (0x2B7222 lo interroga in ciclo); i bit dei tasti sono a 0x0FE70224/0x0FE70228
# (S33_GUI_Quattro_Slot_Snapshot_e_Coda_20261027.md). Modellato a 1 = scansione pronta, nessun tasto premuto. Ipotesi di modello.
MMIO_FILES = {0x0FF63000: {0x4: 0x0010}, 0x0FE70200: {0xC: 0x0001}}
# modello esplicito delle periferiche: l'intera fascia 0x0FE00000-0x0FFFFFFF legge 0 e ignora le scritture, tranne i registri
# con valore modellato (MMIO_FILES). I registri dichiarati uno a uno restano elencati in MMIO per la documentazione.
MMIO_WINDOW = (0x0FE00000, 0x10000000)
# RAM alta non catturata dal dump (buffer immagine/video): modellata come zero; il piano OSD (HI_BASE..) resta il file mappato
HIGH_RAM_ZERO = [(0x0F000000, 0x0F680000), (0x0F6C0000, 0x0F700000)]
# registro tasti nella regione alta (0x180A68 legge l'halfword 0xFFEF037C, bit 6 = tasto logico 0x77): modellato a zero = nessun tasto premuto
# fascia alta delle periferiche 0xFFE00000-0xFFFFFFFF (tasti 0xFFEF037C, display 0xFFEE0660 letti da 0x132C8C): letta 0, scritture ignorate
KEY_HI_ZERO = [(0xFFE00000, 0x100000000)]
SLOT = COUNT   # AkeruOS = id 197 (id 0 deve restare vuoto: significa «nessun reindirizzamento»)   # slot libero nella tabella finestre (197 voci)
CELL = 0x366EA4          # cella della finestra attiva ([[0x14579C]])
ACTIVE_ORIG = 0x783AE8   # AutoScene LiveView nel dump

ASM = '''
 .text
 .global _start
_start:
 mov sp,{stack:#x}
 mov r20,{res:#x}
 ; stato momentaneo del dump: scarto i 2 messaggi pendenti (testa = coda)
 mov r0,{qctl:#x}
 ldh r1,[r0,2]
 sth r1,[r0,0]
 ; registrazione di AkeruOS: nuova tabella finestre = 197 voci Nikon + AkeruOS (id {slot}); id 0 resta vuoto
 mov r0,{table:#x}
 mov r1,newtbl
 mov r2,{count}
 bl copyw
 mov r0,newtbl
 add r0,r0,{newoff}
 mov r1,akeru_win
 st r1,[r0]
 mov r0,{master8:#x}
 mov r1,newtbl
 st r1,[r0]                  ; master+8 = puntatore tabella
 mov r0,{master0c:#x}
 mov r1,{newcount}
 sth r1,[r0]                 ; master+0xC = numero voci
 ; la finestra precedente e' quella attiva ora (solo lettura della cella)
 mov r0,{cell:#x}
 ld r1,[r0]
 mov r2,akeru_win
 st r1,[r2,0x48]
 mov r0,0x1800
 mov r1,{res_k1:#x}
 mov r2,256
 bl copyw
 mov r0,{res:#x}
 add r0,r0,0xc00
 bl walk_timed          ; lista temporizzata del kernel PRIMA dell'apertura
@@RELEASE_SD@@ ; APERTURA tramite l'API Nikon 0x1453E4(id,arg) -> 0x14507C -> manager 0x145180
 mov r0,{slot}
 mov r1,0
 mov r12,0x1453e4
 jl [r12]
 st r0,[r20,0x18]
{more}
 mov r0,{res:#x}
 add r0,r0,0x900
 bl walk_timed          ; lista temporizzata DOPO i cicli
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
 ld r1,[r0,0x44]
 st r1,[r20,0x20]
 mov r1,{cell:#x}
 ld r1,[r1]
 st r1,[r20,0x1c]
 ld r1,[r0,0x90]
 st r1,[r20,0x40]
 ld r1,[r0,0x94]
 st r1,[r20,0x44]
 mov r0,akeru_win
 add r0,r0,0x50
 mov r1,{res_log:#x}
 mov r2,16
 bl copyw
 mov r0,0
 mov r8,1
 trap_s 1

 .align 4
; r0 = destinazione: [0]=count (K+0x54), poi terne (nodo,next,prev) lungo la lista circolare con sentinella K+0x4C, al piu' 33 nodi
walk_timed:
 mov r1,0x1800
 ldh r2,[r1,0x54]
 st.ab r2,[r0,4]
 mov r3,0x184c
 mov r4,33
 mov r5,r3
1:
 ld r6,[r5,0]
 ld r7,[r5,4]
 st.ab r5,[r0,4]
 st.ab r6,[r0,4]
 st.ab r7,[r0,4]
 mov r5,r6
 cmp r5,r3
 beq 2f
 sub.f r4,r4,1
 bne 1b
2:
 j [blink]

 .align 4
; interrupt TIMER0 modellato (motore v14, S33_SLEEPVEC): dopo `sleep 0` (0xB2E08) esegue il gestore originale 0x29F740 (aggiorna K+0x34 e
; scorre la lista temporizzata con 0x2F70C4) e rientra nello scheduler inattivo a 0xB2E0E
tick_stub:
 mov r2,0x1800
 ld r1,[r2,0x204]            ; K[129]: lunghezza del tick in conteggi del timer
 sr r1,[0x21]                ; COUNT0
 mov r12,0x29f740
 jl [r12]
 ld r2,[0x369348]
 mov r12,0xb2e0e
 j [r12]

 .align 4
; interrupt TIMER0 modellato (motore v15, S33_SCHEDVEC): all'ingresso dello scheduler salva il contesto, avanza il timer di 15 tick
; (ipotesi di modello: frequenza reale non misurata), esegue il gestore originale 0x29F740 e rientra in 0xB2D50 con sched_flag=1
sched_tick:
 st.a r0,[sp,-4]
 st.a r1,[sp,-4]
 st.a r2,[sp,-4]
 st.a r3,[sp,-4]
 st.a r4,[sp,-4]
 st.a r5,[sp,-4]
 st.a r6,[sp,-4]
 st.a r7,[sp,-4]
 st.a r8,[sp,-4]
 st.a r9,[sp,-4]
 st.a r10,[sp,-4]
 st.a r11,[sp,-4]
 st.a r12,[sp,-4]
 st.a blink,[sp,-4]
 mov r0,lp_count
 st.a r0,[sp,-4]
 lr r0,[lp_start]
 st.a r0,[sp,-4]
 lr r0,[lp_end]
 st.a r0,[sp,-4]
 lr r0,[status32]
 st.a r0,[sp,-4]
 flag 0                      ; interrupt disattivati come all'ingresso di un ISR
 ld r3,[0x369348]
 ldh r0,[r3,0x18]
 add r0,r0,1
 sth r0,[r3,0x18]           ; K+0x18++ (annidamento ISR): il cancello 0xB2D34 non cambia contesto dentro il gestore
 mov r2,0x1800
 ld r4,[r2,0x204]            ; K+0x204 = periodo del tick in conteggi (1.000.000)
 ld r3,[sched_ticks]         ; tick maturati calcolati dal motore v17 (1..15): COUNT0 resta <= K+0x1FC (15.777.216)
 mov r1,0
1:
 add r1,r1,r4
 sub.f r3,r3,1
 bne 1b
 sr r1,[0x21]
 mov r12,0x29f740
 jl [r12]
 ld r3,[0x369348]
 ldh r0,[r3,0x18]
 sub r0,r0,1
 sth r0,[r3,0x18]           ; uscita dall'ISR: il rientro in 0xB2D50 sceglie il task pronto
 mov r0,0
 sr r0,[0x21]                ; COUNT0=0
 mov r0,0x7fffffff
 sr r0,[0x23]                ; LIMIT0=0x7FFFFFFF: nel simulatore scadenza = istruzioni + (LIMIT0-COUNT0) con segno; -1 scadrebbe subito
 mov r0,0
 sr r0,[0x22]                ; CONTROL0=0: il gestore riarma l'interrupt hardware del timer, che il simulatore lancerebbe al vettore 0x18
                             ; senza poter rientrare (rtie non implementato); nel modello i tick li fornisce questo stub
 ld.ab r0,[sp,4]
 flag r0
 ld.ab r0,[sp,4]
 sr r0,[lp_end]
 ld.ab r0,[sp,4]
 sr r0,[lp_start]
 ld.ab r0,[sp,4]
 mov lp_count,r0
 ld.ab blink,[sp,4]
 ld.ab r12,[sp,4]
 ld.ab r11,[sp,4]
 ld.ab r10,[sp,4]
 ld.ab r9,[sp,4]
 ld.ab r8,[sp,4]
 ld.ab r7,[sp,4]
 ld.ab r6,[sp,4]
 ld.ab r5,[sp,4]
 ld.ab r4,[sp,4]
 ld.ab r3,[sp,4]
 ld.ab r2,[sp,4]
 ld.ab r1,[sp,4]
 mov r0,1
 st r0,[sched_flag]
 ld.ab r0,[sp,4]
 j 0xb2d50
 .align 4
sched_flag:
 .word 0
sched_ticks:                    ; scritto dal motore v17 (= sched_flag+4)
 .word 0

 .align 4
copyw:
 1: ld.ab r3,[r0,4]
 st.ab r3,[r1,4]
 sub.f r2,r2,1
 bne 1b
 j [blink]

 .align 4
; ---- un'iterazione del corpo del task WindowMgr: riceve e smista i messaggi in coda ----
winmgr_pump:
 push_s blink
 push_s r13
 sub sp,sp,16
 mov r13,64                  ; tetto: il Live View riposta tick all'infinito, il vero WindowMgr non termina mai
wp_loop:
 sub.f r13,r13,1
 beq wp_done
 mov r0,sp
 mov r12,0x17bd4c
 jl [r12]
 cmp r0,0
 beq wp_done
 ldh r1,[sp,4]
 cmp r1,0
 beq wp_loop
 ld r0,[sp,0]
 ld r2,[sp,8]
 mov r12,0x169e1c
 jl [r12]
 b wp_loop
wp_done:
 add sp,sp,16
 pop_s r13
 pop_s blink
 j [blink]

 .align 4
; ---- procedura di finestra AkeruOS: r0=finestra r1=msg r2=param ----
akeru_proc:
 push_s blink
 push_s r13
 push_s r14
 push_s r15
 mov r13,r0
 mov r14,r1
 ld r3,[r13,0x90]            ; registro dei messaggi ricevuti (max 16)
 cmp r3,16
 bge nolog
 asl r4,r3,2
 add r4,r4,r13
 st r14,[r4,0x50]
 add r3,r3,1
 st r3,[r13,0x90]
nolog:
 cmp r14,0x4401
 beq do_open
 cmp r14,0x0700
 beq do_next
@@CLOSE_KEY@@ mov r0,0
 b out
do_open:
 ld r0,[r13,0x40]
 cmp r0,0
 bne reject
 mov r0,1
 st r0,[r13,0x40]
 mov r0,0
 st r0,[r13,0x44]
 bl draw_menu
 mov r0,1
 b out
do_next:
 ld r0,[r13,0x40]
 cmp r0,0
 beq reject
 ld r0,[r13,0x44]
 add r0,r0,1
 cmp r0,3
 bne 2f
 mov r0,0
2:
 st r0,[r13,0x44]
 bl draw_menu
 mov r0,1
 b out
do_close:
 ld r0,[r13,0x40]
 cmp r0,0
 beq reject
 mov r0,0
 st r0,[r13,0x40]
 ld r0,[r13,0x48]           ; ritorno alla finestra precedente tramite il manager Nikon
 mov r1,0
 mov r12,0x145180
 jl [r12]
 st r0,[r13,0x94]
 mov r0,1
 b out
reject:
 ld r0,[r13,0x4c]
 add r0,r0,1
 st r0,[r13,0x4c]
 mov r0,0
out:
 pop_s r15
 pop_s r14
 pop_s r13
 pop_s blink
 j [blink]

 .align 4
@@CLEAR_MENU@@

 .align 4
draw_menu:
 push_s blink
 bl clear_menu
 mov r15,0
dm_loop:
 mov r0,10
 mov r2,300
 mov r1,r15
 asl r1,r1,5
 add r1,r1,20
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
newtbl: .space {tblbytes}
 .align 4
akeru_win:
 .word 0
 .word 0,0
 .word akeru_proc            ; +0x0C procedura di finestra
 .space 0x30
 .word 0                     ; +0x40 aperta
 .word 0                     ; +0x44 selezione
 .word 0                     ; +0x48 finestra precedente
 .word 0                     ; +0x4C rifiuti
 .space 0x40                 ; +0x50 registro messaggi (16)
 .word 0                     ; +0x90 conteggio registro
 .word 0                     ; +0x94 ritorno del manager alla chiusura
 .section .stack,"aw",@nobits
 .align 16
 .space 16384
'''

CLEAR_DIRECT = '''clear_menu:                     ; azzera il solo rettangolo del menu nel piano OSD (righe 12..68, colonne 0..359)
 mov r1,0x366abc            ; variabile Nikon: base del piano OSD (0x0F688400 nel dump)
 ld r1,[r1]
 add r3,r1,7680             ; riga 12 * 640 byte
 mov r5,57
 mov r8,0
cm_row:
 mov r6,r3
 mov r7,360
cm_col:
 stb.ab r8,[r6,1]
 sub.f r7,r7,1
 bne cm_col
 add r3,r3,640
 sub.f r5,r5,1
 bne cm_row
 j [blink]
'''
CLEAR_NIKON = '''clear_menu:                     ; cancella il rettangolo (righe 12..68, colonne 0..359) con la routine Nikon 0x17B104(base,riga0,larghezza,righe,piano)
 push_s blink
 mov r0,0
 mov r1,12
 mov r2,360
 mov r3,57
 mov r4,1
 mov r12,0x17b104
 jl [r12]
 pop_s blink
 j [blink]
'''


def nvel_offsets(ram):
    out, pos = [], 0
    while True:
        m = ram.find(b'nvel', pos, 0x1000000)
        if m < 0:
            return out
        pos = m + 1
        if m % 4 == 0 and ram[m - 0x20:m - 0x1c] == b'LNVE':  # solo event group reali (magic LNVE a r0-0xC), non stringhe nel codice
            out.append(m)


def mmio_segments():
    cuts = sorted((a, a + 16) for a in MMIO_FILES)
    lo, segs = MMIO_WINDOW[0], []
    for a, b in cuts:
        if a > lo:
            segs.append((lo, a))
        lo = b
    if lo < MMIO_WINDOW[1]:
        segs.append((lo, MMIO_WINDOW[1]))
    return segs + HIGH_RAM_ZERO + KEY_HI_ZERO

def fix_kernel_lists(work):
    """Riparazione minima, solo nella copia di lavoro, delle liste kernel catturate a meta' nel dump (verificate sul MEMDUMP originale):
    1) MEMDUMP 0x5291C (il task del probe) e' unico membro della coda pronta 0x267C ma con i link verso la lista temporizzata, ed e' a meta' inserimento nell'event group 0x373234 (testa->nodo 0x529D8 ma prev/conteggio no) e nella
       lista temporizzata (prev(0x38D9C)=0x5291C): diventa un task pronto senza attese pendenti;
    2) 0x1571C (stato 0x52D, TCB+0x30 = 0x372D6C) dichiara di attendere l'event group 0x372D64, ma il suo nodo 0x157D8 e' ancora in coda a
       0x3739DC (con next verso il nodo vecchio 0x2D998) e non e' nella lista temporizzata: viene spostato in 0x372D64 e inserito per scadenza."""
    W = lambda a, v: struct.pack_into('<I', work, a, v)
    R = lambda a: struct.unpack_from('<I', work, a)[0]
    H = lambda a, v: struct.pack_into('<H', work, a, v)
    exp = {0x37323C: 0x529D8, 0x529D8: 0x37323C, 0x5291C + 8: 0x52D, 0x38D9C + 4: 0x5291C, 0x157D8: 0x2D998, 0x157D8 + 4: 0x372D6C,
           0x18C58: 0x157D8, 0x3739E4 + 4: 0x157D8, 0x372D6C: 0x372D6C, 0x1571C + 8: 0x52D, 0xAF9C: 0x38D9C,
           0x5291C: 0x184C, 0x5291C + 4: 0xAF9C, 0x5291C + 0x1C: 0x267C, 0x267C: 0x5291C, 0x267C + 4: 0x5291C}
    for a, v in exp.items():
        assert R(a) == v, ('stato del dump inatteso', hex(a), hex(R(a)), hex(v))
    log = []
    def put(a, v, why):
        log.append((hex(a), hex(R(a)), hex(v), why)); W(a, v)
    # 1) MEMDUMP/probe
    put(0x37323C, 0x37323C, 'event 0x373234: testa vuota (next)')
    put(0x529D8, 0x529D8, 'nodo d attesa MEMDUMP auto-collegato (next)'); put(0x529DC, 0x529D8, 'nodo d attesa MEMDUMP (prev)')
    put(0x5291C + 8, 0x2, 'MEMDUMP stato 0x52D -> 2 (pronto, e il task corrente del probe)'); put(0x5291C + 0x30, 0, 'MEMDUMP: nessun oggetto atteso')
    put(0x38D9C + 4, 0xAF9C, 'lista temporizzata: prev(0x38D9C) = 0xAF9C')
    # la coda pronta 0x267C (priorita' di MEMDUMP, anche K+0x2C) contiene gia' MEMDUMP come unico membro, ma i link del TCB puntano ancora alla
    # lista temporizzata: quando il probe si blocca il kernel lo sgancerebbe con quei link vecchi, corrompendo la lista e lasciandolo pronto
    put(0x5291C, 0x267C, 'MEMDUMP: next = testa della coda pronta 0x267C'); put(0x5291C + 4, 0x267C, 'MEMDUMP: prev = testa della coda pronta 0x267C')
    # 2) 0x1571C: fuori da 0x3739DC ...
    put(0x18C58, 0x3739E4, 'event 0x3739DC: ultimo nodo valido -> testa'); put(0x3739E4 + 4, 0x18C58, 'event 0x3739DC: prev testa')
    H(0x3739DC + 0x10, 3); log.append(('0x3739ec', '4', '3', 'event 0x3739DC: conteggio waiter'))
    # ... dentro 0x372D64
    put(0x372D6C, 0x157D8, 'event 0x372D64: testa -> nodo 0x157D8'); put(0x372D70, 0x157D8, 'event 0x372D64: prev testa')
    put(0x157D8, 0x372D6C, 'nodo 0x157D8 -> testa 0x372D64'); put(0x157DC, 0x372D6C, 'nodo 0x157D8 prev')
    H(0x372D64 + 0x10, 1); log.append(('0x372d74', '0', '1', 'event 0x372D64: conteggio waiter'))
    # ... e nella lista temporizzata, per scadenza (0xAF9C 0x173 < 0x1571C 0x17F < 0x38D9C 0x3C1)
    put(0x1571C, 0x38D9C, 'temporizzata: 0x1571C.next'); put(0x1571C + 4, 0xAF9C, 'temporizzata: 0x1571C.prev')
    put(0xAF9C, 0x1571C, 'temporizzata: 0xAF9C.next'); put(0x38D9C + 4, 0x1571C, 'temporizzata: 0x38D9C.prev')
    H(0x1854, 3); log.append(('0x1854', '2', '3', 'K+0x54 conteggio lista temporizzata'))
    return log


def timed_list(buf):
    """Verifica la lista temporizzata del kernel (circolare, doppiamente collegata, sentinella 0x184C): nodi, count e coerenza dei link."""
    count = struct.unpack_from('<I', buf, 0)[0] & 0xffff
    trip = [struct.unpack_from('<III', buf, 4 + 12 * i) for i in range(33)]
    nodes, nxt = [], {}
    for n, nx, pv in trip:
        if n == 0 and nx == 0 and pv == 0 and nodes:
            break
        nodes.append(n)
        nxt[n] = (nx, pv)
        if nx == 0x184c:
            break
    closed = bool(nodes) and nxt[nodes[-1]][0] == 0x184c and nodes[0] == 0x184c
    prev_ok = all(nxt[nodes[i + 1]][1] == nodes[i] for i in range(len(nodes) - 1)) and (nxt[0x184c][1] == nodes[-1] if closed else False)
    return dict(count=count, nodes=[hex(n) for n in nodes[1:]], n_nodes=len(nodes) - 1, closed=closed, links_consistent=prev_ok, count_matches=(len(nodes) - 1 == count))


def build_run(stage, out):
    more = ''
    pump = ' bl winmgr_pump\n'
    post = ' mov r0,0\n mov r1,{msg:#x}\n mov r2,0\n mov r12,0x17bc7c\n jl [r12]\n'
    nav = post.format(msg=0x700) + pump + ((post.format(msg=0x701) + pump) if REAL_KEYS else '')
    shut = ((post.format(msg=0x2180) + pump + post.format(msg=0x2181) + pump) if REAL_KEYS else (post.format(msg=0x701) + pump))
    if stage >= 2:
        more += nav
    if stage >= 3:
        more += ' mov r0,{slot}\n mov r1,0\n mov r12,0x1453e4\n jl [r12]\n st r0,[r20,0x24]\n'.replace('{slot}', str(SLOT)) + pump
    if stage >= 4:
        more += shut
    if stage == 5:  # tre cicli consecutivi apertura -> navigazione -> chiusura (il 1o usa l'apertura di base)
        more = ''
        for i in range(3):
            if i:
                more += (f' mov r0,{CELL:#x}\n ld r1,[r0]\n mov r2,akeru_win\n st r1,[r2,0x48]\n'
                         f' mov r0,{SLOT}\n mov r1,0\n mov r12,0x1453e4\n jl [r12]\n st r0,[r20,{0xc0 + 4 * i}]\n') + pump
            else:
                more += f' ld r0,[r20,0x18]\n st r0,[r20,0xc0]\n'
            more += nav
            more += f' mov r0,akeru_win\n ld r1,[r0,0x44]\n st r1,[r20,{0xd0 + 4 * i}]\n'
            more += shut
            more += (f' mov r1,{CELL:#x}\n ld r1,[r1]\n st r1,[r20,{0xa0 + 4 * i}]\n mov r0,akeru_win\n ld r1,[r0,0x94]\n st r1,[r20,{0xb0 + 4 * i}]\n'
                     f' ld r1,[r0,0x90]\n st r1,[r20,{0xe0 + 4 * i}]\n')
    raw = DUMP.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == DUMP_SHA
    (out / 'probe.s').write_text(ASM.replace('@@RELEASE_SD@@', (' ; il dumper MEMDUMP teneva il volume SD B: post originale 0x1594A4(id 0x1A0000D), il token va al primo task in attesa\n mov r0,0x1a0000d\n mov r12,0x1594a4\n jl [r12]\n st r0,[r20,0x48]\n') if RELEASE_SD else '').replace('@@CLOSE_KEY@@', ' cmp r14,0x2180\n beq do_close\n' if REAL_KEYS else ' cmp r14,0x0701\n beq do_close\n').replace('@@CLEAR_MENU@@', CLEAR_NIKON if NIKON_CLEAR else CLEAR_DIRECT).format(stack=STACK_TOP, res=RES, cell=CELL, more=more, res_k1=RES + 0x100, res_k2=RES + 0x500, res_log=RES + 0x60, qctl=QCTL, slot=SLOT, table=TABLE, count=COUNT, newoff=4 * COUNT, newcount=COUNT + 1, master8=0x366E9C, master0c=0x366EA0, tblbytes=4 * (COUNT + 2)))
    # adattamento del profilo: il simulatore ammette solo accessi allineati, l'ARC700 reale anche non allineati.
    # 0x149134 legge [arg0] di ogni timer UI (tabella 0x443ADC, 40 voci da 0x1C): azzero gli arg0 non allineati nella COPIA di lavoro.
    work = bytearray(raw)
    patched = []
    for i in range(40):
        a = 0x443ADC + 0x1C * i
        v = struct.unpack_from('<I', work, a)[0]
        if v & 3:
            patched.append((hex(a), hex(v)))
            struct.pack_into('<I', work, a, 0)
    # ipotesi di modello (--presignal): gli eventi senza waiter risultano gia' segnalati (bit tutti alti), cosi' le attese del task corrente
    # ritornano subito invece di richiedere un cambio di contesto che il profilo non ha. Non e' un comportamento verificato.
    presignaled = []
    if '--presignal' in sys.argv or '--presignal-all' in sys.argv:
        pos = 0
        while True:
            m = bytes(work).find(b'nvel', pos, 0x1000000)
            if m < 0:
                break
            pos = m + 1
            if m % 4:
                continue
            r0 = m - 0x14
            if '--presignal-all' in sys.argv or struct.unpack_from('<H', work, r0 + 0x10)[0] == 0:
                struct.pack_into('<I', work, r0 + 0x18, 0xFFFFFFFF)
                if '--presignal-all' in sys.argv:  # lista waiter vuota: il task corrente (MEMDUMP) non resta incodato due volte senza scheduler
                    struct.pack_into('<II', work, r0 + 8, r0 + 8, r0 + 8)
                presignaled.append(hex(r0))
    klists = fix_kernel_lists(work) if FIX_KLISTS else []
    (out / 'profile_patches.json').write_text(json.dumps(dict(timer_arg0_zeroed=patched, events_presignaled=presignaled, kernel_lists_fixed=klists), indent=2) + '\n')
    (out / 'ram_working_copy.bin').write_bytes(bytes(work[BASE:]))
    (out / 'image.ld').write_text(f'PHDRS {{ ram PT_LOAD FLAGS(7); stk PT_LOAD FLAGS(6); }}\nSECTIONS {{\n . = {BASE:#x}; .dumpram : {{ *(.dumpram) }} :ram\n . = {CODE:#x}; .text : {{ *(.text) }} :ram\n . = {STACK_BASE:#x}; .stack (NOLOAD) : {{ *(.stack) }} :stk\n}}\n')
    for cmd in ([TOOLCHAIN / 'arc-elf32-as', '-mcpu=arc700', '-EL', '-o', out / 'probe.o', out / 'probe.s'],
                [TOOLCHAIN / 'arc-elf32-objcopy', '-I', 'binary', '-O', 'elf32-littlearc', '-B', 'arc', '--rename-section', '.data=.dumpram,alloc,load,contents', out / 'ram_working_copy.bin', out / 'ram.o'],
                [TOOLCHAIN / 'arc-elf32-ld', '-EL', '-e', hex(CODE), '-T', out / 'image.ld', '-o', out / 'image.elf', out / 'probe.o', out / 'ram.o']):
        pr = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
        assert pr.returncode == 0, pr.stderr
    (out / 'result.bin').write_bytes(bytes(0x1000))
    (out / 'hi_ram.bin').write_bytes(bytes(HI_SIZE))
    for a, regs in MMIO_FILES.items():
        b = bytearray(16)
        for off, v in regs.items():
            struct.pack_into('<H', b, off, v)
        (out / f'mmio_{a:x}.bin').write_bytes(bytes(b))
    assert sha(LAB / 'install/bin/arc-elf32-run') == json.loads(BUILD.read_text())['experimental_sha256']
    # + [0x427B00] svuotato a ogni istruzione: il pari (altro processore/task) consuma lo slot della mailbox (send 0x2D51EC, recv 0x33737C)
    # + [0x36A640] |= 1: il ciclo 0x23F494 attende questo flag, impostato da un altro task (ipotesi di modello, non verificata)
    pokes = ','.join([f'{m - 0x14 + 0x18:x}:ffffffff' for m in nvel_offsets(bytes(work))] + ['36a640:1', '427b00!ffffffff']) if POKE_ALL else ''
    sleepvec = []
    if SCHEDTICK:
        nm = subprocess.run([str(TOOLCHAIN / 'arc-elf32-nm'), str(out / 'image.elf')], capture_output=True, text=True).stdout
        sym = {l.split()[2]: l.split()[0] for l in nm.splitlines() if len(l.split()) == 3}
        sleepvec += ['-e', f"S33_SCHEDVEC={sym['sched_tick']},{sym['sched_flag']}"]
    if TICK:
        nm = subprocess.run([str(TOOLCHAIN / 'arc-elf32-nm'), str(out / 'image.elf')], capture_output=True, text=True).stdout
        sleepvec = ['-e', 'S33_SLEEPVEC=' + next(l.split()[0] for l in nm.splitlines() if l.endswith(' tick_stub'))]
    cmd = ['podman', 'run', '--rm', '--network', 'none', *(['-e', 'S33_POKES=' + pokes, '-e', 'S33_ONLY=5291c'] if pokes else []), *sleepvec, '--memory', '2g', '--volume', f'{LAB}:/engine:ro', '--volume', f'{out}:/result:rw', IMAGE,
           'timeout', f"{SIM_TIMEOUT}s", '/engine/install/bin/arc-elf32-run',
           '--memory-mapfile', '/result/result.bin', '--memory-region', f'{RES:#x},4096',
           '--memory-mapfile', '/result/hi_ram.bin', '--memory-region', f'{HI_BASE:#x},{HI_SIZE:#x}',
           *[x for a in MMIO_FILES for x in ('--memory-mapfile', f'/result/mmio_{a:x}.bin', '--memory-region', f'{a:#x},16')],
           '--memory-fill', '0', *[x for lo, hi in mmio_segments() for x in ('--memory-region', f'{lo:#x},{hi - lo:#x}')], '/result/image.elf']
    if FULL:
        cmd.insert(cmd.index('/engine/install/bin/arc-elf32-run') + 1, '--trace-insn')
        pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        keep = [l for l in pr.stdout if not l.startswith('0x')]
        pr.wait()
        run = subprocess.CompletedProcess(cmd, pr.returncode, ''.join(keep), '')
    else:
        run = subprocess.run(cmd, capture_output=True, text=True, timeout=SIM_TIMEOUT + 140)
    (out / 'sim.log').write_text(run.stdout + run.stderr)
    rb = (out / 'result.bin').read_bytes(); global TIMED; TIMED = (timed_list(rb[0xc00:0xc00 + 4 + 12 * 33]), timed_list(rb[0x900:0x900 + 4 + 12 * 33])); global EXTRA; EXTRA = struct.unpack('<64I', rb[0xa0:0x1a0])
    rb = rb; res = struct.unpack('<18I', rb[:72]); log = struct.unpack('<16I', rb[0x60:0xa0]); k1 = rb[0x100:0x500]; k2 = rb[0x500:0x900]
    return run.returncode, res, (out / 'hi_ram.bin').read_bytes(), k1, k2, log

def main():
    root = ROOT / 'Risultati/Runtime_Kernel/Akeru_Window_Profile' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    stages = {}
    only = [int(x) for x in sys.argv[1:] if x.isdigit()] or [1, 2, 3, 4]
    for stage in only:
        out = root / f'stage{stage}'
        out.mkdir(parents=True)
        rc, res, hi, k1, k2, log = build_run(stage, out)
        kdiff = [(0x1800 + 4 * i, struct.unpack_from('<I', k1, 4 * i)[0], struct.unpack_from('<I', k2, 4 * i)[0]) for i in range(256) if k1[4 * i:4 * i + 4] != k2[4 * i:4 * i + 4]]
        nz = [i for i, b in enumerate(hi) if b]
        stages[stage] = dict(exit=rc, open_ret=res[6], reopen_ret=res[9], active_cell=hex(res[7]), selection=res[8], flag=res[14], rejects=res[15],
                             log_count=res[16], close_ret=res[17], msgs=[hex(x) for x in log[:res[16]]], win=hex(res[13]), pixels=len(nz), values=sorted({hi[i] for i in nz}),
                             kernel_diff=[(hex(a), hex(b), hex(c)) for a, b, c in kdiff], hi=hi)
        stages[stage]['timed_list_before'], stages[stage]['timed_list_after'] = TIMED
        if stage == 5:
            stages[5]['cycles'] = dict(open_ret=list(EXTRA[8:11]), selection_before_close=list(EXTRA[12:15]), close_ret=list(EXTRA[4:7]),
                                       cell_after_close=[hex(x) for x in EXTRA[0:3]], log_count_after_close=list(EXTRA[16:19]))
    # valutazione: fasi 1-3 verificate, fase 4 (ritorno al Live View tramite manager) registrata come tentativo
    verdict = {}
    if all(k in stages for k in (1, 2, 3)):
        s1, s2, s3 = stages[1], stages[2], stages[3]
        h1, h2 = s1['hi'], s2['hi']
        diff12 = sum(1 for x, y in zip(h1, h2) if x != y)
        verdict['stage1_open_via_manager'] = (s1['exit'] == 0 and s1['open_ret'] == 1 and s1['active_cell'] == s1['win'] and s1['flag'] == 1
                                              and s1['msgs'][:3] == ['0x4403', '0x4401', '0x4405'] and s1['pixels'] > 0)
        verdict['stage2_key_via_windowmgr'] = (s2['exit'] == 0 and s2['selection'] == 1 and s2['msgs'][-1] == ('0x701' if REAL_KEYS else '0x700') and diff12 > 0)
        def marker_pixels(h):
            B = 0x0F688400 - HI_BASE
            return sum(1 for i, b in enumerate(h) if b and 0 <= (i - B) % 640 < 12 and 12 <= (i - B) // 640 <= 68)
        verdict['clean_redraw_single_marker'] = marker_pixels(h1) > 0 and marker_pixels(h2) == marker_pixels(h1)
        verdict['stage3_reopen_cycle_and_guard'] = (s3['exit'] == 0 and s3['rejects'] == 1 and s3['flag'] == 1 and s3['active_cell'] == s3['win']
                                                    and s3['msgs'][(5 if REAL_KEYS else 4):(11 if REAL_KEYS else 10)] == ['0x4403', '0x4404', '0x4406', '0x4402', '0x4401', '0x4405'])
    if 4 in stages:
        log = (root / 'stage4' / 'sim.log').read_text().splitlines()
        first = next((l for l in log if not l.startswith(('S33_DSP', 'S33_AUX'))), '')
        if stages[4]['exit'] == 124:
            first = ('timeout senza ritorno al chiamante. Senza modelli ferma su 0x23C798 (nodo waiter auto-collegato, nessun altro task che segnali). '
                     'Con S33_POKE_ALL=1 S33_FORCE_FULL=1 (event group LNVE, flag 0x36A640, mailbox 0x427B00 modellati) avanza ma non rientra in 3000 s: causa non stabilita')
        verdict['stage4_close_return_liveview'] = dict(done=stages[4]['exit'] == 0 and stages[4]['flag'] == 0, exit=stages[4]['exit'], active_cell_after_close=stages[4]['active_cell'], active_cell_is_original_liveview=stages[4]['active_cell'] == hex(ACTIVE_ORIG), blocked_by=first)
    if 5 in stages:
        c = stages[5]['cycles']
        verdict['stage5_three_cycles'] = dict(done=stages[5]['exit'] == 0 and c['open_ret'] == [1, 1, 1] and c['close_ret'] == [1, 1, 1] and len(set(c['cell_after_close'])) == 1,
                                             exit=stages[5]['exit'], cycles=c, expected_cell_is_nikon_redirect=c['cell_after_close'][0] == '0x99d4a4')
    for k, v in stages.items():
        v.pop('hi', None)
    ok = all(v is True for v in verdict.values() if isinstance(v, bool))
    ev = dict(status=('PASS_STAGES_1_3' if all(k in stages for k in (1, 2, 3)) else 'PARTIAL_STAGES_' + ''.join(map(str, sorted(stages)))) if ok and verdict else 'INCOMPLETE', dump_sha256=DUMP_SHA, verdict=verdict, stages=stages,
              mmio_declared_one_by_one=len(MMIO), mmio_window=[hex(MMIO_WINDOW[0]), hex(MMIO_WINDOW[1])], mmio_modeled_files={hex(a): {hex(o): hex(v) for o, v in r.items()} for a, r in MMIO_FILES.items()},
              limits='Profilo da dump; motore DSP sperimentale; periferiche 0x0FE00000-0x0FFFFFFF modellate (lettura 0, scritture ignorate, 0x0FF63004 bit4=1); tabella timer UI: arg0 non allineati azzerati nella copia; '
                     'tabella finestre estesa a 198 voci (id 197 = AkeruOS); messaggi pendenti del dump scartati; WindowMgr eseguito come corpo del ciclo, non come task schedulato; tasto 0x700 = id reale ma semantica non provata.')
    (root / 'evidence.json').write_text(json.dumps(ev, indent=2) + '\n')
    print(ev['status'], json.dumps(verdict))
    assert hashlib.sha256(DUMP.read_bytes()).hexdigest() == DUMP_SHA, 'originale modificato'
    print(root)

if __name__ == '__main__':
    main()
