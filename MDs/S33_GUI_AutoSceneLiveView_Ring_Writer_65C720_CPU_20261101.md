# S33 — Ring writer 0x65C720 del sottosistema gate AutoSceneLiveView: decodifica completa e prova CPU (iterazione 39)

**Data**: 1 novembre 2026 (iterazione 39 del ciclo Vibe offline)
**Verificatore**: `Python_Trace_Scripts/s33_verify_aslv_ring_writer_cpu.py`
**Esito**: **PASS_ASLV_RING_WRITER_CPU** — 22/22 casi CPU su byte originali,
due esecuzioni identiche:
`Risultati/GUI_S33/aslv_ring_writer_cpu_20261101T201306910162Z/` e
`Risultati/GUI_S33/aslv_ring_writer_cpu_20261101T201333569437Z/`
(evidenze byte-identiche a meno di `utc` e conteggio istruzioni).
**Stato**: studio offline, NON_INSTALLARE, nessun hardware. Circa 10% invariato.

## Domanda

Chiude il punto aperto it.37 (prossimo passo (a) del rapporto
`S33_GUI_AutoSceneLiveView_Handler_100_CPU_20261101.md`): il writer del
sottosistema gate, 0x65C720 (5 chiamanti: 2 in 0x4405, 0x440E, handler 0x100 a
0x65B200, 0x4006), era decodificato solo staticamente e mai eseguito. Domanda:
0x65C720 resetta davvero `[ctx+0xC]` e il byte gate `[0x47BBC8]`, accoda un
singolo "motivo di riapertura" nel ring a `[0x47BBB8+4·gate]` con incremento,
e consulta la coda di servizio 0x4111/0x4110 prima di restituire `r15`?

## Decodifica (byte originali, blocco 2, finestra 0x65C720..0x65C920)

Prologo/epilogo (millicode **provato in CPU** per la prima volta per questa
coppia di ingressi):
- `bl 0x334118` spinge r20,r19,r18,r17,r16,r15,r14,r13 (8 registri, 32 byte);
- epilogo `mov sp,fp; ld.ab fp,[sp,4]; b 0x33416C` li ripristina e carica
  `blink` dalla cella pushata (`ld.ab blink,[sp,4]`; **`ld.ab` ha EA=rA con
  post-incremento di rA**, confermato da sem7.c e dal comportamento in CPU);
- frame deterministico: fp=0xC8EFD8, locali fp-3..fp-1, argomento di
  0x12B0DC = fp-0xC = 0xC8EFCC (verificato nel log di tutti i casi full-path).

Corpo (`r16`=node, `r17`=0x135A84(), `r13`=0, `r19`=0x137774(0), `r15`=1,
`r20`=0xDE3E4() non usato nei rami, `r18`=0):
1. **Gate 1**: `C7E04()==0` → ritorno 0, NESSUNA scrittura (casi 0-1 negativi).
2. **Gate 2**: `17BE18(0,0x3180,0x3180)!=0` → ritorno 0; poi
   `17BE18(0,0x3181,0x3181)!=0` → ritorno 0, NESSUN reset (casi 1-2).
3. **Reset incondizionato** (solo dopo i due gate): `[ctx+0xC]:=0` e
   `[0x47BBC8]:=0` (gate), `12B0DC(fp-0xC)`.
4. **Dispatch sul modo** (getter REALE 0xCAD30 → `[0xC8E80C]`):
   - modo 0x7D: azzera fp-3..fp-1; `127984(fp-3,fp-2,fp-1)` scrive 3 out-byte
     (stub banco con fixture OUTCELL); se b1≠0 ∨ b2≠0 ∨ b3≥0xA → `r18=C7BDC()`,
     altrimenti r18 resta 0 (LDB zero-extend + blt_s con segno: su 0..255
     l'esito coincide, vedi revisione C5);
   - altro modo: `C7E04()==1` → `r18=127284()`, altrimenti r18=-1.
5. **Dispatch (al più UN enqueue per invocazione, catena if/elif)**:
   - r19≠0: r17 bit3 → ENQ 0xB; elif bit2 → 0xD; elif bit4 → 6; elif bit1 → 4;
     else `127278()`: ==0 ∧ r18==0 → ENQ 3 (r15=0); ≠0 → ENQ 5 (r15=0);
     r18≠0 → **scrittura ctx** `[ctx+0xC]:=1, [ctx+0xD]:=0, r15=0`, NESSUN
     enqueue;
   - r19==0: `127278()!=0` → ENQ 5; else r18==0 → ENQ 0xC; else scrittura ctx.
   - ENQ(v): rilegge il gate (`ldb [ring+0x10]`), `add2 r1,ring,r0` =
     **ring + 4·gate (scala ×4**, sem7.c `add2_L_r_r`: `SLLSI(C,2)`),
     `st v,[r1]`, `gate:=gate+1`.
6. **Sezione coda di servizio**:
   - `17BE18(0,0x4111,0x4111)!=0` → `14941C()`; se 0 → `177460()`;
     `17BF60(0,0x4111,0x4111)`; r15=1; `20E814(node,0x4111,0)`;
   - elif `17BE18(0,0x4110,0x4110)!=0` → `14941C()`; se 0 → `177460()`;
     `17BF60(0,0x4110,0x4110)`; r15=1 (NESSUN 20E814);
   - elif `177484()!=0` → `14941C()`; se 0 → `177460()`; r15=1;
   - finale: `C9750()==0` → r15=0; `C975C(1)`; ritorno r15.

Pool (word verificate nel dump): 0x65C90C=0x3181, 0x65C910=0x681F5C (ctx),
0x65C914=0x47BBB8 (ring), 0x65C918=0x4111, 0x65C91C=0x4110.
Census `bl 0x65C720` (objdump 16 blocchi + scansione LE + brute-force
codifiche, agente): **5 siti** {0x659A80, 0x659C14, 0x65A08E, 0x65B200,
0x65CAEE}, zero riferimenti non-bl (0x65CAEE è `bl_s` 16-bit 0xFF0D).

## Casi CPU (22, entry 0x65C720, byte originali; 12°-22° con controlli negativi)

| # | caso | esito chiave |
|---|------|---------------|
| 0 | gate1_c7e040 | C7E04()==0 → ret 0, nessuna scrittura (sentinelle intatte) |
| 1-2 | gate2_q3180/q3181 | query pendenti → ret 0, NESSUN reset (gate resta 0x5A) |
| 3-6 | enq_0xB/0xD/6/4 | bit3/2/4/1 → ring[0]=valore, gate 0→1, ret 1 |
| 7 | bits_priority | r17=0x1E (4 bit) → SOLO 0xB, gate=1 (if/elif) |
| 8-11 | enq_3/5/0xC/5 | catene 127278/r18, r15=0, ret 0 |
| 12-13 | ctxwrite | r18≠0 → [ctx+0xC]=1, [ctx+0xD]=0, NESSUN enqueue, gate=0 |
| 14 | mode7d_clean | 127984 con out-byte 0 → niente C7BDC, UNA sola chiamata C7E04, ENQ 3 |
| 15 | mode7d_c7bdc | out-byte 0,0,0xA → C7BDC ret 0x33 → r18≠0 → ctx write |
| 16 | q4111_post | 14941C/177460/17BF60(0,0x4111,0x4111)/20E814(node,0x4111,0), ret 1 |
| 17 | q4111_941cne0 | 14941C≠0 → NO 177460, post comunque |
| 18 | q4110_post | ENQ 3 (r15=0) poi 0x4110 pendente → 17BF60(0,0x4110,0x4110), r15 RESTORED a 1 |
| 19 | 177484_restore | coda vuota ma 177484≠0 → 14941C/177460, r15 ripristinato 1, nessun post |
| 20 | c9750_zero | C9750()==0 → ret 0 nonostante l'enqueue |
| 21 | add2_micro | entry 0x65C7F0 con gate fixture 3: parola a 0x47BBC4 = ring+4·3, gate=4 (**scala ×4 provata in CPU**) |

Negativi inclusi: sentinella `[0x47BBB4]` (slot 0 del lettore) mai scritta,
ring[1..2] intatti nei casi a enqueue singolo, ctx+0xD intatto senza ctx write,
`CNT` esatto + sentinella "nessuna chiamata extra" in ogni caso.

## Consequence per il sottosistema gate (rifinisce l'interpretazione it.37)

1. **Il "ring" è un canale a slot 0 rinnovato**: 0x65C720 resetta SEMPRE il
   gate a 0 prima del dispatch, scrive il motivo a `[0x47BBB8]` (slot 0) e
   lascia gate=1. L'accumulo oltre lo slot 0 (valori 9/0xA dei writer
   0x4110/0x4111, non ancora provati in CPU) può avvenire solo in invocazioni
   successive SENZA un 0x65C720 intermedio.
2. **Coerenza writer/lettore chiusa in CPU**: il lettore h100 (it.37) legge
   `word[0x47BBB4+4·gate]`; con gate=1 consuma `[0x47BBB8]` = il motivo
   appena scritto (it.37 aveva solo la mappa statica di 0x65E900).
3. **Lezione registri vivi (estende la 753)**: le query 0x3180/0x3181
   caricano r1/r2 con le costanti del pool, che sopravvivono come leftover
   fino alla sezione coda (0x4111/0x4110); nel dispatch `mov r0,r17` (solo
   ramo r19≠0) sovrascrive il leftover di 127284, quindi i due bracci passano
   a 127278 un r0 DIVERSO (r17 vs ritorno di 127284).
4. **add2 = rB + (rC<<2)**: la scala ×4 è sia nei sorgenti del motore
   (sem7.c) sia provata in CPU (caso 21).

## Revisione indipendente

Agente `rw-review-39` (tools.agents.spawn, completato e integrato; appunti in
`tmp/it39/REVISIONE_rw_review_39.md`, originali in /tmp/rwrev39/): **CONFERMATO**
la decodifica su tutta la finestra, con precisazioni integrate:
- 0x65CAEE è `bl_s` 16-bit, non `bl` 32-bit (census 5 siti confermato con
  tre metodi indipendenti; zero riferimenti non-bl; il linear sweep objdump
  desincronizza sulla pool 0x659594-98 e senza sync forzato attribuirebbe i
  due siti di 0x4405 all'handler 0x4401);
- C5: `ldb` (senza .x) zero-estende e `blt_s` è con segno, ma su operando
  0..255 l'esito coincide: b3≥0xA (inclusi i byte ≥0x80) chiama C7BDC;
- ld.ab EA=rA con post-incremento (sem7.c);
- nessun altro writer di 0x47BBB8/0x47BBC8/0x47BBB4 nella finestra, nessuna
  lettura `[ctx]` fuori da +0xC/+0xD;
- limite dichiarato: la chiusura transitiva delle callee non è completa;
  la RAM runtime (gate incluso) non è nel dump; il banco CPU non è stato
  rieseguito dall'agente (come richiesto).

## Comandi ed esiti

- `python3 Python_Trace_Scripts/s33_verify_aslv_ring_writer_cpu.py`
  → PASS_ASLV_RING_WRITER_CPU **20261101T201306910162Z** + riesecuzione
  identica **20261101T201333569437Z** (22/22 casi, fault 0xDEADB001..0x16).
- Regressioni post-PASS: 4/4 PASS — `s33_verify_aslv_helper_d098_cpu.py`,
  `s33_verify_aslv_b060_arg18_clear_cpu.py`,
  `s33_verify_service_raise_pending.py`,
  `s33_verify_snapshot_capture_record_init_cpu.py`
  (eseguiti direttamente senza pipe, log /tmp/reg39_*).
- Statico nel verificatore: pool (5 word), freeze finestre (RW 0x200 byte,
  millicode, mode getter/pool), sem7.c add2, census bl 0x65C720 (5 siti),
  SHA finestre nelle evidenze.

## Fixture, assunzioni e limiti

- ctx 0x681F5C fixture 0xD0 byte sentinella 0xA5 (+8/+0xFF, +9/+0x5A come
  it.37); modo 0xC8E80C fixture; ring 0x47BBB0..0x47BCD0 fixture con gate
  iniziale 0x5A (nei casi full-path) per provare il reset; gate/coda/RAM
  runtime nel gap di load 0x428600..0x5FE800: NON verificabili dal dump.
- Stub (~17) con **ritorni a sequenza** (RETSEQ, 4 per sid) perché
  17BE18/C7E04 sono chiamate ripetute con semantiche diverse; stub speciale
  127984 che scrive i 3 out-byte da fixture OUTCELL; caso micro two-pass
  (blink land ricavato via objdump: `mov blink,<land>; push_s blink` —
  l'epilogo millicode legge blink dalla MEMORIA, non dal registro).
- Originali eseguiti: tutto il corpo 0x65C720, millicode push/pop
  (0x334118/0x33416C), getter modo 0xCAD30, sequenza enqueue 0x65C7F0..0x65C81E.
- NON provati in CPU: produttori runtime del gate (chi chiama 0x65C720 con
  quali condizioni), contenuti reali delle code 0x3180/0x3181/0x4111/0x4110,
  writer 0x4110/0x4111 (9/0xA), scheduling/concorrenza tra i 5 chiamanti,
  hardware. Significato dei motivi {3,4,5,6,0xB,0xC,0xD} = interpretazione
  coerente con it.37, non etichette Nikon.

## Prossimo passo (non ripetitivo)

(a) **CPU dei writer 0x4110/0x4111** (accodano 9/0xA con guardia
`word[0x47BBB4+4·gate]!=0xA` secondo it.37): eseguirli con byte originali e
fixture del ring permette di verificare l'append senza reset e completa la
famiglia dei writer del sottosistema gate.
(b) Alternativa: produttori dell'evento 0x100 (13 siti 17BF60, in particolare
0x659D3C dentro 0x4405) per capire chi attiva la riapertura riconsegnata da
h100 path A.
Il punto it.39 è CHIUSO: non rieseguire il verificatore ring writer.
