# AutoSceneLiveView — Consumatore 0x65B3A8 (eventi 0x380/0x400) provato in CPU (iterazione 48)

Data: 1° novembre 2026. Verificatore:
`Python_Trace_Scripts/s33_verify_aslv_consumer_380_400_cpu.py`.
Esito: **PASS_ASLV_CONSUMER_380_400_CPU 20261101T210144995277Z**, riesecuzione
byte-identica **20261101T210207318802Z** (confronto JSON ex-utc: identico, sha
eddbb0649be605cd), 16/16 casi CPU su byte originali, regressioni 4/4 PASS
post-PASS. Chiude il punto it.47(a) del rapporto
[S33_GUI_AutoSceneLiveView_Append_Writers_4110_4111_CPU_20261101.md](S33_GUI_AutoSceneLiveView_Append_Writers_4110_4111_CPU_20261101.md).
NON_INSTALLARE; circa 10% invariato.

## Domanda

L'handler 0x65B3A8 (registro p3, eventi 0x380/0x400, record 0x783B58/0x783B68),
unico chiamante bl dell'handler 0x4111 (it.47) e primo decrementatore del gate
individuato nel firmware, era decodificato solo staticamente. Esegue davvero
il CONSUMO del ring (lettura gate, lettura `word[0x47BBB4+4*gate]`,
decremento del gate se la parola vale 0xA)? Chiama davvero l'handler 0x4111
con (node, 0, 0) quando la coda resta piena dopo la purga? E cosa inoltra a
0x20E814 nei due rami? Come si coordina con il ciclo
0x65C720→0x4110/0x4111→h100?

## Identificazione e census

Registro p3 (block 03, base 0x669800): 0x783B58/0x783B5C = (0x380 → 0x65B3A8),
0x783B68/0x783B6C = (0x400 → 0x65B3A8); 0x4110 → 0x65CC40, 0x4111 → 0x65CCC8,
terminatore (0, 0x20E814) a 0x783C40/44 (conferme it.47). Census LE su tutti
i 16 blocchi a ogni allineamento: 0x65B3A8 compare SOLO nei due campi handler
del registro. Census bl su tutti i 16 blocchi: **0x65B3A8 zero chiamanti**
(callback puro); **0x65CCC8 unico bl a 0x65B53A**, dentro questo handler
(riconferma it.47). Zero rami in entrata da fuori finestra (revisione agente).

## Decodifica (byte originali, block 2, finestra 0x65B3A8..0x65B5D4)

Prologo: `push_s blink; bl 0x334124` (millicode push r17,r16,r15,r14,r13),
`st.aw fp; mov fp,sp`; r14=node, r17=ev, r16=arg, r13=0.

Gate d'ingresso: `1707D8(4)`; `C9BF8()==1` → uscita (ret = valore di C9BF8);
mode getter `0xCAD30()==0x7E` → uscita; `CF060(1)`; quindi **gate di stato**
su `[ctx+4]` (ctx = pool 0x65B5BC = 0x681F5C): `==8` → `[ctx+4]:=0` e prosegue;
`{0,3}` prosegue; **ogni altro valore esce con ritorno = puntatore ctx**
(r0 non è più riscritto dopo 0x65B3DE). Poi `135A84(ctx, stato, arg)` — qui
r0 è il PUNTATORE ctx, NON node — bit1 → uscita (ret 2); `C8BA0(0)!=0` →
uscita (ret 1).

Dispatch `cmp r17,1024`: ev==0x400 vs ELSE (nessun confronto esplicito con
0x380). Polarità OPPOSTA del gate zoom `14A1F8` vs 0x64, provata in CPU sul
valore di confine 0x64 (casi 6/7): **0x400 `bls_s` (fallisce se ≤0x64),
0x380 `blo_s` (fallisce se <0x64)** — a zoom 0x64: 0x400 fallisce, 0x380
passa. Gate comuni `1493D8()==1`, `149474()==1`, `CD514()==1`.

- ev 0x400 ok: `[ctx+0x20] (0x681F7C) := 0` (byte, r15=0), forward
  `65B71C(node,0x400,arg)`, coda comune. Fail: `14948C()==0` → `65D008/
  65CE88`, **r13 := 0x1493A4** (pool 0x65B5C4), coda comune.
- else (0x380) ok con `CDACC()!=0`: `65D008/65CE88`, poi `[ctx+0x20]:=1`,
  forward `65B71C(node,0x380,arg)`, coda comune; con `CDACC()==0`: coda comune
  DIRETTA (nessuna scrittura, nessun forward). Zoom fail: `149474()==0` →
  `65D008/65CE88`, **r13 := 0x14938C** (pool 0x65B5C8), e ARMA il timer:
  `14918C(node,0xC)==0` → `14905C(node,0xC,400,400,0)` (solo ramo 0x380).

Coda comune (0x65B4C2): r15 = 0x149028 (pool 0x65B5CC);
`149028(node,k)` per k∈{1,2,3,4,6} via `jl_s [r15]`; `65D1CC(node)`;
`65D8B4`; `145920`; `145150(node)`; **`177484()`** decide:

- **coda vuota** → r13≠0: `DECD4(0)/DD094/149DF4(1)`, `[ctx+4]:=4`,
  **`jl_s [r13]` LINKED** (blink = 0x65B566: il callee RIENTRA e la coda
  continua a 0x65B566): `14A1F8()>0x64` → uscita, else
  `14905C(node,3,1000,1000,0)`. r13==0: stato {2,3} → `149474()!=0` uscita;
  `[ctx+4]:=5`; `14A1F8()>0x64` uscita; `CAD30()==0x2C` →
  `14905C(node,1,500,500,0)`.
- **coda non vuota** → purga `177460/17743C/177484`:
  - ancora piena → `bl 0x65CCC8` (handler **0x4111 REALE**, finestra .h41
    originale) con **(node, 0, 0)** — l'handler appende 0xA al ring (it.47),
    la sua ri-notifica interna è `20E814(node, 0, 0)` (vedi sotto) — poi
    `20E814(node, 0x4111, arg)` (pool 0x65B5D0) e uscita.
  - svuotata → **CONSUMO**: `ld.as r2 → [0x65B388] = 0x47BBB8`;
    `ldb r1,[r2,0x10]` (gate 0x47BBC8); gate==0 salta (`ble_s`, byte
    zero-esteso: preso SOLO a 0); `ld.as r0 → [0x65B390] = 0x47BBB4`;
    `add2_s r0 += 4*gate` → `ld_s r0,[r0]` = ultima voce (ring[gate-1]);
    `==0xA` → `sub_s r1,r1,1; stb_s r1,[r2,0x10]` → **gate := gate-1**
    (0x65B524/26, unico decremento noto); la parola NON viene azzerata.
    Poi `65D8B4`; `145150(node)`; `20E814(node, 0x4111, arg)`; uscita.

Uscita unica: `b 0x65B1B8` (disp −1024) → `mov sp,fp; ld.ab fp,[sp,4]`;
`b 0x334184` (disp −0x32703C, eseguita CORRETTAMENTE dal motore pinnato,
coerente con i precedenti it.36 −3298300 e traccia it.47) → pop millicode
r17,r16,r15,r14,r13 + blink: bilancio del push 0x334124 provato dal valore
di ritorno al banco. Nessuna uscita salta l'epilogo (revisione agente: 38
rami enumerati, tutti i percorsi convergono).

## Scoperta nuova: il forward interno dell'handler 0x4111

A 0x65CD3C/0x65CD3E (`mov_s r1,r13 / mov_s r2,r15`): il tail dell'handler
0x4111 inoltra `20E814(node, ev IN INGRESSO, arg IN INGRESSO)`, NON la
costante 0x4111. it.47 non poteva distinguerlo perché entrava sempre con
ev=0x4111. Nella chiamata del consumatore (node,0,0) la ri-notifica interna è
**`20E814(node, 0, 0)`** e i successivi `14941C/177460` ricevono r1=0 (casi
13/14, provato in CPU con l'handler REALE). Il valore 0x4111 compare SOLO
nel forward proprio del consumatore (pool 0x65B5D0).

## Banco e protocollo di frame (originale)

Finestre byte-originali caricate agli indirizzi originali: `.h380`
(2, 0x65B3A8..0x65B5D4, 556 byte), `.poolh` (2, 0x65B388..0x65B398: pool
ring/TBL letti via `ld.as [pcl,-97/-98]`, EA=(PC&~3)+imm·4, lezione it.37),
`.epi` (2, 0x65B1B8..0x65B1C4), `.mili` (0, 0x334100..0x3341E4), `.h41`
(2, 0x65CC18..0x65CD54, handler 0x4111 reale, freeze it.47), `.epi9`
(2, 0x659588..0x659594). Nei casi 13/14 il sim esegue il corpo REALE di
0x65CCC8 con il suo frame completo (push 0x33412C / epilogo 0x659588 / pop
0x334194) dentro la catena del consumatore. 34 stub a sequenza RETSEQ
(8 valori per sid, ordine di chiamata), logger 16B/chiamata, fixture ring
0x47BBB0..0x47C070 con gate a 0x47BBC8, ctx 0x681F5C 0xD0 byte sentinella
0xA5.

## Casi CPU (16, tutti PASS x2)

| # | caso | essenziale |
|---|---|---|
| 0 | exit_c9bf8 | C9BF8 ret 1 → uscita immediata, ret 1 |
| 1 | exit_mode_7e | mode 0x7E → uscita, ret 0x7E |
| 2 | exit_state7 | stato 7 → uscita, **ret = ctx 0x681F5C**, stato intatto |
| 3 | bit1_exit | 135A84 bit1 → uscita, ret 2 |
| 4 | c8ba0_exit | C8BA0 ret 1 → uscita, ret 1 |
| 5 | ev400_pass | stato 3 passa il gate SENZA scritture; [ctx+0x20]:=0; forward 65B71C(node,0x400,arg); coda vuota, stato 3 → 149474 ret 1 → uscita ret 1 |
| 6 | ev400_zoomfail_r13_timer | zoom 0x64 fallisce bls → 14948C==0 → 65D008/65CE88, r13=0x1493A4; coda vuota → [ctx+4]:=4, jl_s [r13] RIENTRA a 0x65B566 → 14A1F8 0x64 → 14905C(node,3,1000,1000,0) |
| 7 | ev380_zoom64_pass_state5 | zoom 0x64 passa blo → CDACC==0 → NESSUN forward/scrittura; coda vuota → [ctx+4]:=5; mode 0x2C → 14905C(node,1,500,500,0) |
| 8 | ev380_gatefail_r13 | 1493D8==0 → r13=0x14938C; timer 14918C(node,0xC)==0 → 14905C(node,0xC,400,400,0); [ctx+4]:=4; jl_s [r13] → 14A1F8 0x65 → uscita ret 0x65 (r2=400 persiste in tutta la coda) |
| 9 | consume_decrement | purge svuota → consumo: gate 2, ring[1]=0xA → gate 2→1; 65D8B4(0xA,1,RING)/145150(node,1,RING)/20E814(node,0x4111,arg); parola NON azzerata; 65DAD0/14941C mai chiamati |
| 10 | consume_gate0 | gate 0 → lettura/decremento saltati, gate resta 0 |
| 11 | consume_noA | gate 3, parola 9 → nessun decremento, gate resta 3 |
| 12 | consume_gate_ff | gate 0xFF, parola a 0x47BBB4+4·0xFF = **0x47BFB0** = 0xA → gate 0xFF→0xFE |
| 13 | append_real_4111 | purge lascia la coda PIENA → **handler 0x4111 REALE** con (node,0,0): appende 0xA a ring[1], gate 1→2, ctx +0x10/+0x14/+0xD, ri-notifica interna 20E814(node,0,0) + 14941C/177460 con r1=0; poi il consumatore: 20E814(node,0x4111,arg) con **arg r16 preservato** (0x65CCC8 non tocca mai r16/r17) |
| 14 | append_real_guard | ring[0]=0xA → la guardia REALE blocca l'append: gate resta 1, ring[1] sentinella intatta; i tail comunque eseguiti (65DAD0(0xA,...), ctx, 20E814/14941C/177460 con r1=0) |
| 15 | state8_clear_consume | stato 8 → [ctx+4]:=0 e il flusso PROSEGUE; CDACC!=0 → [ctx+0x20]:=1 + forward 65B71C(node,0x380,arg); purge svuota → consumo gate 1/ring[0]=9 senza decremento; **[ctx+4]=0 finale persiste** |

Negativi e sentinelle in ogni caso: slot −1 (0x47BBB4) mai scritto, ctx+0xC
sentinella, conteggio chiamate esatto + "nessuna chiamata extra" (voce di log
successiva con sid 0), valori di ritorno al banco (RETCELL), celle fixture
intatte dove il firmware non deve scrivere, log a0/a1/a2 esatti con i
leftover r1/r2 ricalcolati staticamente (stato a SC8BA0, 6/ARG/400 nella
coda, RING/gate nel consumo).

## Conseguenze sul sottosistema gate (ciclo CHIUSO)

1. **Il ring del sottosistema gate è ora una CODA CONSUMATA, provata in CPU
   su entrambi i lati**: 0x65C720 resetta e scrive slot 0 (it.39),
   0x4110/0x4111 appendono 9/0xA (it.47), h100 legge la voce corrente
   `word[0x47BBB4+4*gate]` (it.37) e **0x65B3A8 consuma e DECREMENTA il gate
   quando la voce vale 0xA** (it.48). Il decremento cancella solo l'indice,
   NON la voce.
2. La distribuzione dei compiti tra i due rami della coda non vuota:
   coda ancora piena dopo la purga → l'handler 0x4111 REALE viene invocato
   in-linea come "funzione" (ev=0, arg=0) e il suo append avviene PRIMA del
   ritorno; coda svuotata → il consumatore legge/decrementa e ri-pubblica
   0x4111 al registro p1 (via 20E814) perché il ciclo continui.
3. La ri-notifica interna dell'handler 0x4111 dipende dall'evento con cui è
   CHIAMATO, non dal suo id: dal registro arriva (node,0x4111,arg) e ripubblica
   0x4111; dal consumatore arriva (node,0,0) e ripubblica evento 0. Per la
   coda AkeruOS questo significa che un evento 0x4111 consegnato dal registro
   produce DUE notifiche p1 (una interna, una dal consumatore 0x380/0x400),
   con semantiche diverse.
4. Gli stati finestra {4,5} prodotti qui ([ctx+4]:=4 con r13≠0, :=5 con
   r13==0) e l'azzeramento dello stato 8 completano la mappa dei writer di
   [ctx+4] dell'handler (3 store: 0x65B3E8/0x65B562/0x65B594 — census
   revisione: NESSUN altro writer nella finestra).
5. `jl_s [r13]` (1493A4/14938C) è una chiamata LINKED che rientra a
   0x65B566: NON è un tail-call. Assunzione di banco: quelle funzioni
   ritornano (comportamento reale non provato, vedi Limiti).

## Comandi ed esiti

- `python3 Python_Trace_Scripts/s33_verify_aslv_consumer_380_400_cpu.py` →
  PASS_ASLV_CONSUMER_380_400_CPU **20261101T210144995277Z**; riesecuzione
  **20261101T210207318802Z** identica. Run intermedie con correzioni oracolo
  (documentate, 12/15 → 13/15 → 15/15 prima dell'aggiunta del caso 16):
  20261101T205024662712Z (12/15, fail caso 6), 205121817276Z (idem),
  205159003496Z (fail caso 8), 205257838652Z (fail caso 12),
  205349618360Z (fail caso 13), 205437362499Z (15/15 PASS) e
  205505051898Z (identica) — le due ultime sono le evidenze 15-casi; le
  evidenze FINALI 16-casi sono le due run 2101Z sopra.
- Regressioni post-PASS finali (eseguite direttamente, log /tmp/reg48b_*):
  aslv_helper_d098 PASS 20261101T210236011164Z, aslv_b060_arg18_clear PASS
  20261101T210256024919Z, service_raise_pending PASS 20261101T210315Z,
  snapshot_capture_record_init PASS 20261101T210320169589Z.
- Evidenze: [run 1](../Risultati/GUI_S33/aslv_consumer_380_400_cpu_20261101T210144995277Z/),
  [run 2](../Risultati/GUI_S33/aslv_consumer_380_400_cpu_20261101T210207318802Z/),
  [revisione agente](../Risultati/GUI_S33/aslv_consumer_380_400_agent_review_consumer48_20261101.md).

## Revisione indipendente

Agente **consumer-review-48** (revisione statica ex-novo: disassembly propri
di tutti i 16 blocchi, census LE a ogni allineamento, census bl/b/bcc/j,
target dei b 32-bit ricalcolati con la formula estratta da decode7.c del
motore pinnato, condizioni bcc dalle tabelle COND3_*/COND_* di arc-desc.h,
round-trip assembler byte-esatto per le istruzioni chiave, freeze ricavati e
confrontati): **C1–C9 CONFERMATI** byte-esatti (gate chain, polarità
opposte, coda comune, rami coda vuota/non vuota, consumo, epilogo, census,
finestra .h41 senza toccare r16/r17, nessuna uscita senza teardown, nessun
delay slot nei corpi, zero rami in entrata). **Due controesempi nell'oracolo**
individuati PRIMA della mia correzione empirica e coincidenti con i fault
osservati nelle run intermedie: (A) FF_WORD = 0x47BFB8 → corretto 0x47BFB0
(0x47BBB4+4·0xFF); (B) forward interno atteso 0x4111 → reale r1=0
(`mov_s r1,r13` a 0x65CD3C). Entrambi corretti e il PASS finale li incorpora.
Precisioni integrate nella docstring: dispatch 0x400-vs-else, ordine
65D008→65CE88→[ctx+0x20]:=1→forward, 65D1CC riceve node. Gap di copertura
segnalato (stato 8, [ctx+0x20]:=1 con forward) chiuso con il caso 16.

## Limiti e non dimostrato

Statica + 16 casi CPU sintetici; nessun hardware/boot/rendering/scatto;
NON_INSTALLARE; circa 10% invariato. ctx 0x681F5C, ring 0x47BBB0..0x47C070 e
gate 0x47BBC8 sono RAM runtime nel gap di load 0x428600..0x5FE800:
fixture-imposte, NON verificabili dal dump. I ritorni degli stub sono
imposti dal banco. **L'ipotesi che 0x1493A4/0x14938C ritornino** (continuazione
a 0x65B566) è un'assunzione di banco: il comportamento reale di quelle due
funzioni non è provato. Chi produce a runtime gli eventi 0x380/0x400 e
0x4110/0x4111, e la schedulazione, restano aperti; il significato dei motivi
{3,4,5,6,9,0xA,0xB,0xC,0xD} del ring resta interpretazione. La funzione
0x65B71C (forward zoom) e i servizi 149028/65D1CC/65D8B4/145920/177460/
17743C/177484 restano stub. La sopravvivenza di r16 attraverso callee
profondi è convenzione (nel banco gli stub la preservano; 0x65CCC8 provato
non tocca r16/r17). V1.1 vs V1.0 non confrontato.

## Fonti

- Verificatore: [s33_verify_aslv_consumer_380_400_cpu.py](../Python_Trace_Scripts/s33_verify_aslv_consumer_380_400_cpu.py)
- Evidenze congelate: `verified_evidence.json` delle due run finali (windows
  sha256, pool, registry, census LE/bl, freeze hex, 16 casi con fault
  0xDEADB001..0x10)
- Precedenti: it.47 (append writer, census 0x65CCC8), it.39 (ring writer),
  it.37 (h100, sottosistema gate, lezione ld.as), it.34/36 (epiloghi e
  millicode), it.25/28/30 (registro p3, wrapper, chiusura)
- Revisione indipendente: agente consumer-review-48 (appunti /tmp/rev48,
  copia in Risultati/GUI_S33/)
