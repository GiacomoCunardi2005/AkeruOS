# AutoSceneLiveView: handler 0x100 (0x65B1CC) decodificato e CPU-provato — il ciclo 0x100 → helper → 0x81 con ri-armamento dello stato 6

Iterazione 37 (Vibe offline, 1° novembre 2026). Chiude il punto aperto
dall'iterazione 36 (rapporto
[S33_GUI_AutoSceneLiveView_Helper_D098_CPU_20261101.md](S33_GUI_AutoSceneLiveView_Helper_D098_CPU_20261101.md)):
il primo chiamante dell'helper 0x65D098 — l'handler 0x100 a 0x65B1CC,
record ev 0x0100 del registro p3 a 0x783B50 — era noto solo come writer
di `[ctx+4]` 2/6 (census it.25) e come primo chiamante dell'helper. Mai
decodificato né eseguito.

## Domanda

Cosa fa l'handler 0x100 attorno alla chiamata all'helper? In particolare:
(1) quando il byte gate `[0x47BBC8]` è > 0, consegna davvero
`(node, ev, arg)` ORIGINALI all'handler 0x81 (0x65B060) e apre una
finestra scelta tramite una tabella runtime? (2) quando il gate è 0,
arma davvero lo stato 6 (`[ctx+4]:=6` con i byte `+0x1C:=1, +0x1D:=0,
+0x1E:=1`) sotto le condizioni modo/stato/guardia? (3) il ciclo completo
0x100 → helper (stato6+guardia → stato2 + consegna 0x81 → teardown →
stato 0) può RI-ARMARE lo stato 6 nella stessa invocazione? (4) qual è
l'EA vera della `ld.as` a 0x65A09A il cui commento GNU `;0x659fa8`
punta in mezzo al codice?

## Decodifica (GNU ARC700, byte originali, blocco 2; revisione indipendente CONFERMA)

```
65b1cc: push blink; bl 0x334128 (push r16,r15,r14,r13); st.aw fp
        r14=node, r16=r1(ev), r15=r2(arg)
head:   17083C(1), 1707D8(2), 149028(node,0xA),
        0x65D098(node)  <- HELPER (r1/r2 = leftover 0xA/arg)
        0xC7DD8(r0 = ritorno dell'helper, passato invariato)
        0x65C720(node)  <- writer del ring gate (vedi sotto)
gate:   r0 = byte[0x47BBB8+0x10] (pool 0x65B388; LDB_S UNSIGNED,
        cmp_s 0; ble => equivalente a "byte == 0")
 >0 (path A):
        [ctx+4]:=2 WORD (pool 0x65B38C=0x681F60; r1 resta 0x681F60
        anche per le due chiamate successive)
        C5870(2)   <- r0 è la costante 2 dello store di stato, NON il
                      gate byte; ritorno inutilizzato (chiama internamente
                      0x158D04(0x42700002,0x80,0,0))
        CF538(0)   <- setter: [0x3657BA]:=0
        0x65B060(node, ev, arg)  <- RICONSEGNA ORIGINALE (r16/r15)
        rilegge il gate byte, word = [0x47BBB4 + 4*gate] (pool 0x65B390)
        packed = 0x65E900(word); 1453E4(packed & 0xFF, packed >> 16)
        tail b 0x659F8C -> pop r16,r15,r14,r13 (millicode 0x33418C)
 ==0 (path B):
        modo = 0xCAD30() ORIGINALE
        modo 0x7E: CD5AC()==0 -> CD5BC(1), 145D1C(0) -> [ctx+0x30],
                   D2470(0), 1453E4(0x87,0);
                   CD5AC()!=0: arg==0xFFFFFF80 oppure D10E8()!=0 ->
                   145D1C(0) -> [ctx+0x34], 149028(node,9),
                   143AFC(0x27), 143AFC(0x28), 1439D4(0x26) -> cade in
                   0x65B2AE; altrimenti 65D590(node,0x86) e USCITA
                   (nota: 65D590 azzera [ctx+0x30] e [ctx+0x34])
        modo != 0x7E: r13 = ctx (pool 0x65B394)
        0x65B2AE: C7E04()==1 -> gate byte[ctx+0xC]==0 -> uscita
        0x65B2BC: [ctx+4]==2 oppure D10C4()!=0 -> 0x65B2CA; else uscita
                  (r0 viene RICARICATO con la parola di stato: le
                  chiamate successive ricevono lo stato, non il ritorno
                  di C7E04)
        0x65B2CA: 136280(), DE254() (r0 = 0 se ==0x15, else 1),
                  C01EC(r0), guardia = 0xCA310() ORIGINALE
        guardia==1 -> [ctx+4]:=6 (0x65B2EA), [ctx+0x1C]:=1,
                     [ctx+0x1D]:=0, [ctx+0x1E]:=1 (BYTE), 65DB78(),
                     145150(node), 14905C(node,4,1000,1000,0),
                     176828(3,1,0x32), bl.d 145C3C delay r0=0x30D40,
                     176828(3,0,0x32) -> uscita
        guardia!=1 -> 17BF60(0,0x80,0x307F), 17BF60(0,0x400C,0x400C),
                     bl.d 12CAD4 delay r0=0x00B00106, modo==0x7D ->
                     D0CE8()/D0CF0(), 141CE8(0,0,0), modo==0x15 ->
                     D0CAC(), 17083C(2), 1453E4(4, byte[ctx+0x2A])
```

Epilogo condiviso 0x659F8C (4 tail: 0x65B384 handler 0x100, 0x65BA3A
handler 0x7CEA, 0x65C6F2 handler 0x581/0x2701, 0x65D1B8 fn 0x65D13C):
`mov sp,fp; ld.ab fp; b 0x33418C` → `r12=4, r13=0x10, b 0x3341D2` →
pop r16,r15,r14,r13,blink; bilanciato con il push 0x334128.

## Il mapper 0x65E900 (word del ring → finestra packed)

Corpo originale in blocco 2, 9 chiamanti bl: 0x659A9A e 0x659C6E
(handler 0x4405), 0x65A0A2 (0x440E), 0x65B230 (handler 0x100),
0x65CB0C (0x4006), 0x65D8CA/0x65D966/0x65DAEC/0x65DE3A (famiglia
0x65Dxxx). Semantica CPU-provata:

- word == 0 → ritorno 0 immediato, SENZA chiamate;
- altrimenti `149028([0x681FBC], 6)` — chiude la risorsa 6 del nodo
  salvato dall'apertura 0x4401 in ctx+0x60 (pool 0x65E8FC=0x681FBC);
- k = word − 3; se k > 10 → 0; jump table a 0x65E936 (byte `13 0e 11
  0b 15 15 15 15 06 13 08`, `add1_s` → target = 0x65E936 + 2·byte):

| word | packed | (idx, arg) |
|---|---|---|
| 3 | 0x000000A7 | (0xA7, 0) |
| 4 | 0x000100A7 | (0xA7, 1) |
| 5 | 0x000300A7 | (0xA7, 3) |
| 6 | 0x000400A7 | (0xA7, 4) |
| 7..10 | 0 | (0, 0) |
| 11 | 0x0000004D | (0x4D, 0) |
| 12 | 0x000000A7 | (0xA7, 0) |
| 13 | 0x000200A7 | (0xA7, 2) |

Il chiamante estrae `extb` (idx) e `>>16` (arg) e chiama
`0x1453E4(idx, arg)` (wrapper del commutatore WindowManager, it.18).
La mappa è confermata byte per byte dalla revisione indipendente.

## Il sottosistema gate (RAM runtime nel gap di load)

0x47BBB4/0x47BBB8/0x47BBC8 NON sono coperti da alcun blocco TBM
(gap 0x428600..0x5FE800): sono celle RAM runtime, contenuto NON
verificabile dal dump — nel verificatore sono fixture.

- **0x65C720** (5 chiamanti bl: 0x659A80/0x659C14 in 0x4405, 0x65A08E
  in 0x440E, 0x65B200 in handler 0x100, 0x65CAEE in 0x4006): azzera
  `[ctx+0xC]` (0x65C780) e `[0x47BBC8]` (0x65C786), poi accoda una word
  ∈ {3,4,5,6,0xB,0xC,0xD} in `[0x47BBB8+4·gate]` e INCREMENTA il byte
  gate (0x65C81A/1C e 0x65C85C/5E). Un ring di "motivi di riapertura"
  con contatore.
- **Writer aggiuntivi** (revisione): handler 0x4110 accoda 9 e handler
  0x4111 accoda 0xA (entrambi incrementano, con guardie
  `word[0x47BBB4+4·gate] != 0xA`).
- **Reader del byte**: handler 0x100 (0x65B206/0x65B228), 0x440E
  (0x65A092, cella diretta), 0x180 (0x65C31E, esce se != 0), 0x4405
  (0x659A86/0x659C3A, pattern gate+tabella+0x65E900), 0x4006
  (0x65CAF2/0x65CB04), 0x65C720 interno.
- **Alias strutturale**: 0x65D390 (pool 0x65D484) e handler 0x7D40
  (pool 0x65AC48) usano 0x47BBB8 come BASE di un array di record
  (stride 10, campi a +0x14..+0x1C), sola lettura; 0x65C920 è
  `return &0x47BBB8`.
- **Produttori dell'evento 0x100** (revisione C6): esistono — 13 siti
  diretti via 0x17BF60 con r1=0x100 (incluso 0x659D3C DENTRO l'handler
  0x4405) più 1 via coda 0x169EB4. Pattern ricorrente (0x80/0x81) →
  (0x100/0x101).

## LEZIONE TOOLCHAIN: commento GNU errato per LD.AS (oracolo assemblatore)

`ld.as r0,[pcl,-240]` a 0x65A09A (handler 0x440E, bytes `10 17 00 f6`):
- `arc-elf32-as -mcpu=arc700` assembla `ld.as r0,[pcl,-240]` in
  ESATTAMENTE quei byte; `-960` non è encodabile (richiede limm);
- il campo s9 RAW è −240, quindi l'EA runtime è
  `(pc&~3) + (−240)·4 = 0x659CD8`, dove il payload contiene il pool
  `0x0047BBB4`;
- GNU objdump mostra l'operando `-240` e il commento `;0x659fa8` =
  `(pc&~3)+(−240)` SENZA la scala ×4: **il commento è ERRATO per
  LD.AS** (round-trip assemblatore→disassemblatore verificato). Il
  plain LD (es. `[pcl,-76]`, `[pcl,-4]`) non è scalato e lì GNU è
  corretto. Coerente con la regola CPU it.40 `(PC&~3)+imm·4`.
- Prova CPU (caso `ldas_ea_659cd8`): eseguendo i byte originali con la
  finestra pool originale 0x659CD4..CDC, il simulatore carica
  `0x47BBB4` — EA confermata in esecuzione, non solo staticamente.

## LEZIONE ISA: LDB_S è UNSIGNED

Progettando il controllo negativo "gate byte 0xFF → estensione del
segno → path B", l'esecuzione ha mostrato il path A. Il manuale
ARCompact (5115-029, sezione Load/Store) è esplicito: "Byte and word
loads are zero or sign extended to 32-bits by using the sign extend
suffix: .X" e LDB_S = "Load unsigned byte"; il motore implementa
`ZEXTQISI` (sem7.c, ldb_s_abu). Quindi il `cmp_s r0,0; ble` a
0x65B20A equivale a "gate byte == 0" e i byte ≥ 0x80 prendono il
path A. Coerente con it.42 (`ldw_s.x` "halfword CON segno"). Il caso
è stato riformulato come test del path A con indice ring grande.

## Comandi eseguiti ed esiti

- `python3 Python_Trace_Scripts/s33_verify_aslv_h100_cpu.py`
  → **PASS_ASLV_H100_CPU** prima esecuzione completa
  **20261101T194718263688Z** + riesecuzione identica
  **20261101T194824137656Z** (12/12 casi CPU in entrambe,
  fault 0xDEADB001..0C; static: registro p3, 20 pool, LE scan su 4
  celle, census bl 0x65B1CC/0x65C720/0x65E900, 12 freeze opcode,
  inventario finestre con SHA-256).
- Regressioni **10/10 PASS**: snapshot record init **194846240683Z**,
  guard setter census **194847043201Z**, service raise pending, wm
  notify registry, notify reactors, aslv slot handlers, aslv open
  wrapper, aslv close handler, aslv b060 arg18 clear, aslv helper
  d098 (esiti completi nel checkpoint).
- Decodifica statica di supporto: `tmp/it37/h100_decode.py` (sola
  lettura); oracolo assemblatore `tmp/it37/ldas/`.
- Fasi intermedie documentate: 8 evidenze parziali
  `aslv_h100_cpu_20261101T19{3636,3825,3906,4250,4333,4420,4501,4545}Z`
  (census statico sempre PASS; correzioni oracolo: r1=0x681F60 per
  C5870/CF538, r0 costante 2 per C5870, ricarica dello stato in r0
  prima di 136280/D10C4, r1/r2 residui 0xB/0xFA dopo il teardown
  reale di 0x65B060, r1=9 dopo `mov r1,9`; riformulazione del caso 11
  dopo la lezione ISA LDB_S).

## Casi CPU (finestre byte-originali; ingresso 0x65B1CC con
r0=NODE, r1=EV=0x100, r2=ARG=0x5678; helper e 0x65B060 stubbati con
ritorno 0x77 tranne il caso catena)

1. `ldas_ea_659cd8` — micro: byte originali 0x65A09A..0x65A0A6 +
   pool originale 0x659CD4..CDC, fixture `[0x47BBB8]=0x5151`,
   0x65E900 stub → il `ld.as` carica il pool 0x47BBB4 e la word 0x5151
   arriva allo stub: EA 0x659CD8 provata in CPU.
2. `h100_pathA_tbl4` — gate=2, tabella[2]=4: `[ctx+4]:=2`,
   riconsegna `65B060(NODE,EV,ARG)`, 0x65E900 REALE →
   `149028(0xBEEF,6)` + `1453E4(0xA7,1)`; ret = ritorno 1453E4.
3. `h100_pathA_tblB` — gate=3, tabella[3]=0xB → `1453E4(0x4D,0)`.
4. `h100_pathA_tbl0` — gate=1, tabella[1]=0 → 0x65E900 ritorna 0
   PRECOCE: NESSUNA `149028(saved,6)`, `1453E4(0,0)`.
5. `h100_pathB_arm6` — gate=0, modo 0x2B, stato 2, C7E04≠1,
   DE254=0x15, guardia 1 → ARM: `[ctx+4]=6`, `+1C=1, +1D=0, +1E=1`,
   65DB78(1), 145150(node), 14905C(node,4,1000),
   176828(3,1,0x32), 145C3C(0x30D40), 176828(3,0,0x32).
6. `h100_pathB_guard0` — guardia 0 → 17BF60(0,0x80,0x307F),
   17BF60(0,0x400C,0x400C), 12CAD4(0x00B00106), 141CE8(0,0,0),
   17083C(2), 1453E4(4,0x37); lo stato RESTA 2 (nessuna scrittura 6).
7. `h100_pathB_state5` — stato 5, D10C4=0 → uscita, nulla scritto
   (controllo negativo del gate di stato; D10C4 riceve r0=5).
8. `h100_pathB_mode7e` — modo 0x7E, CD5AC=0 → CD5BC(1),
   145D1C(0)→`[ctx+0x30]=0x42`, D2470(0), 1453E4(0x87,0).
9. `h100_chain_rearm` — helper REALE + 0x65B060 REALE: stato 6 +
   guardia 1 + gate 0 + modo 0x2B + arg18 0x100 + D10C4=1: testa →
   helper (stato 2 + consegna 0x81) → teardown completo reale
   (cancel 0x100, stato 0, gate celle 0, coda modo 2B fino
   65CF58) → il gestore continua su path B, legge stato 0, D10C4=1
   → **RI-ARMA lo stato 6** nella STESSA invocazione (finale
   `[ctx+4]=6`, `+1C=1, +1D=0, +1E=1`). Risposta alla domanda (3).
10. `h100_7e_arg80` — modo 0x7E, CD5AC≠0, arg=0xFFFFFF80 →
    `[ctx+0x34]=0x99`, 149028(node,9), 143AFC(0x27/0x28),
    1439D4(0x26), poi arm 6.
11. `h100_7e_d10e8` — arg≠0x80, D10E8=0 → 65D590(node,0x86) e uscita.
12. `h100_gate10_far` — path A con indice ring 0x10: tabella letta a
    0x47BBF4 (fixture) = 3 → `1453E4(0xA7,0)`; dimostra letture
    oltre i 4 slot minimi.

Finestre originali: `.mili` 0x334100..0x3341E4, `.gget`, `.modeget`+
`.modepool`, `.epi` 0x659588, `.epi2` 0x659F8C, `.poolctx`,
`.poolg`, `.b60` 0x65B060..0x65B1CC, `.h100` 0x65B1CC..0x65B3A8
(0x1DC byte, con i pool 0x65B388..0x65B3A4), `.helper`, `.e900`
0x65E8FC..0x65E974, `.pool9` 0x659CD4, `.ldas` 0x65A09A.

## Controlli negativi

- Gate a due stadi (path A vs B) isolato dai casi 2-5/12; il caso 7
  prova che D10C4=0 blocca PRIMA di qualunque scrittura; il caso 6
  prova che con guardia≠1 lo stato 6 NON viene scritto.
- 0x65E900 con word 0: NESSUNA chiamata (caso 4) contro word 4/0xB/3
  con la chiamata 149028(saved,6) (casi 2/3/12).
- Registri vivi tracciati: r1=0x681F60 dopo lo store di stato,
  r0=costante 2 per C5870, r0=stato per 136280/D10C4, r1/r2 residui
  0xB/0xFA dopo il teardown reale, r1=9 dopo `mov r1,9`, r1/r2
  ORIGINALI ev/arg per la riconsegna a 0x65B060.
- Assert "nessuna chiamata oltre il conteggio atteso" e sentinelle di
  memoria in ogni caso; celle gate/tabella fixture intatte dove il
  firmware non deve scrivere.
- Il caso 11 originale (gate 0xFF, estensione del segno) è stato
  riformulato — non indebolito — dopo la prova ISA che LDB_S è
  unsigned: il suo sostituto copre un percorso NON coperto prima
  (indice ring > 4).

## Significato per AkeruOS

L'handler 0x100 è il punto di raccordo tra il completamento posticipato
(stato 6 → helper → 0x81 → teardown) e il meccanismo di riapertura: lo
stesso evento che consuma lo stato 6 può RI-ARMARLO immediatamente
(caso catena) quando il gate ring è vuoto e la guardia è 1; quando il
ring contiene un motivo (gate > 0), forza lo stato 2, riconsegna
l'evento ORIGINALE (ev, arg) all'handler 0x81 e converte l'ultima voce
del ring in una richiesta di apertura finestra (0xA7/0x4D con arg
0..4) tramite 0x65E900. La coda AkeruOS non può assumere che un evento
0x100 consegnato all'AutoSceneLiveView lasci lo stato a 0: può lasciarlo
a 6 (ri-armato) o a 2 (path A). Inoltre: il ritorno del gestore è il
ritorno dell'ultima chiamata del percorso (non un codice di stato), e il
byte gate va letto come UNSIGNED (ble ≡ ==0).

## Limiti e non dimostrato

Statica + 12 casi CPU con fixture: nessun hardware/boot/rendering/
scatto/persistenza; NON_INSTALLARE; ~10% invariato. La tabella
0x47BBB4 e il byte 0x47BBC8 sono RAM runtime (gap di load): i valori
nei casi sono imposti dal banco, la mappa word→finestra di 0x65E900 è
invece codice originale provato. ~30 callee stub; il ring writer
0x65C720 e i writer 0x4110/0x4111 sono solo statici (decodificati, mai
eseguiti in CPU). Produttori runtime del gate e scheduling non provati;
concorrenza tra i 5 chiamanti dell'helper e i lettori del ring aperta.
Il "significato" delle finestre 0xA7 (167) e 0x4D (77) e dei valori
{3..13} del ring resta interpretazione. Il caso 11 (gate 0xFF su
hardware) non è deciso: l'ISA dice unsigned, il motore conferma, ma
nessuna prova hardware.

## Fonti

- Verificatore: [s33_verify_aslv_h100_cpu.py](../Python_Trace_Scripts/s33_verify_aslv_h100_cpu.py)
- Evidenze finali: [Risultati/GUI_S33/aslv_h100_cpu_20261101T194718263688Z/](../Risultati/GUI_S33/aslv_h100_cpu_20261101T194718263688Z/) (+ riesecuzione e 4 run parziali con le correzioni d'oracolo documentate)
- Revisione indipendente `h100-review-37`: C1-C7 CONFERMATI con 4
  precisioni integrate (uscita immediata 65D590, [ctx+0x30/0x34] =
  ritorno di 145D1C, gate riletto non rivalidato, C5870/CF538
  semantica); census doppi (sweep + scanner byte-level) identici;
  appunti /tmp/h100rev37 (REVISIONE.md, CONTROLLENTE.md).
- Oracolo assemblatore ld.as: tmp/it37/ldas; manuale ISA
  outputs/gnu_arc700_aux/sources/ARCompact_5115-029.txt (LDB_S
  "Load unsigned byte"; suffisso .X per il segno).
- Precedenti: it.36 (helper 0x65D098), it.34 (handler 0x81), it.30
  (handler 0x4405), it.28 (apertura/wrapper), it.25 (slot handlers,
  census writer), it.40 (regola EA ld.as).
