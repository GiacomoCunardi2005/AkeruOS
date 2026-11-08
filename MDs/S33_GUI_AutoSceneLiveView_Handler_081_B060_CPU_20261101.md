# AutoSceneLiveView: handler evento 0x81 (0x65B060), cancellatore di [ctx+0x18] e teardown — CPU 2026-11-01 (it.34)

## Domanda

Punto aperto it.30(a) — **produttore/consumatore di [ctx+0x18]**
(0x681F74) della finestra AutoSceneLiveView (ctx 0x681F5C) dopo
l'apertura. In particolare: chi cancella lo 0x100 residuo che
l'handler di chiusura 0x4405 lascia quando la riapertura differita
viene bloccata da coda/cfg (it.30 casi 7-9: «[ctx+0x18] resta
0x100»).

La sessione it.33 aveva affrontato la stessa domanda ed era stata
interrotta per assenza di output: sopravvivevano solo i censimenti
in `tmp/it33/` (mai verificati in CPU). Questa iterazione recupera
quei censimenti, completa la decodifica e chiude il punto con un
verificatore CPU nuovo.

## Risultato verificabile e significato

**PASS_ASLV_B060_HANDLER_081**: 9/9 casi CPU su byte ORIGINALI
(finestra `.b60` 0x65B060..0x65B1CC del blocco 2, sha256
`77419751be83b8d70f230e25fb97ecca07c573853a89ccd42ca18a6493bddfb8`),
x2 run identiche (evidenze byte-identiche salvo `utc`):

- run 1: `Risultati/GUI_S33/aslv_b060_cpu_20261101T190743571858Z/`
- run 2: `Risultati/GUI_S33/aslv_b060_cpu_20261101T190802453662Z/`

(Le run preliminari 185813438027Z/185835686880Z sono identiche ma
riportano l'attribuzione errata dei siti 0x65AC0C/0x65AC18 corretta
dalla revisione; le run definitive sopra incorporano
l'attribuzione corretta.)

**0x65B060 è l'handler dell'evento 0x0081** della finestra
AutoSceneLiveView: registro p3 (0x783B08) record 8, ev a 0x783B48,
handler a 0x783B4C — unica LE dell'indirizzo in tutti i blocchi.
L'identificazione «handler 0x81 (0x65B060)» era un'etichetta statica
del censimento writer it.28; qui il record del registro è citato
byte-esatto e il corpo è eseguito per la prima volta in CPU.

Struttura decodificata (tutti i rami provati in CPU):

1. **Prologo**: `0x17083C(1, r1, r2)`; `0x148E68(ret)`; ret==0 ->
   `0x148E14(1)`. Gli argomenti r1/r2 di ingresso sono **MORTI**
   dopo il salvataggio in r17/r16 (millicode 0x334124 spilla
   r17..r13): valgono solo come argomenti vivi delle prime tre
   chiamate.
2. **Gate di rientro**: `0xD103C(0)`; `0xD10C4(ret)`; se
   `ret==1 ∧ [ctx+4]==3` -> **ritorno anticipato** che NON tocca
   [ctx+0x18], NON chiama 0xD10A8/0xCB5B0/0x143AFC e **restituisce
   r0 = [ctx+4]** (il valore dello stato, caso 3: _ret 3). Con
   stato≠3 il gate NON blocca (caso 8: d10c4==1, stato 5 ->
   cancellazione normale).
3. **Cancellatore**: `0xD10A8(0)`; se `[ctx+0x18]==0x100` ->
   `[ctx+0x18]:=0` + `0xCB5B0(0x100)`; ==0x101 o altro valore ->
   NON scritta, nessuna chiamata (casi 2 e 9). **Questo risponde
   alla domanda it.30(a)**: lo 0x100 differito bloccato viene
   consumato dall'handler 0x81, non da un writer esterno.
4. **Teardown** (stato [ctx+4] ∈ {2,3}):
   `[ctx+0x1E]:=1`, `[ctx+4]:=0`, `[ctx+0x1D]:=0`,
   `[[0x3669EC]+0xF0]:=0` e `[0x442734]:=0` — **le stesse due celle
   gate che l'handler 0x4405 azzera quando 0x14504C(node,0x12)==0x55**
   (it.30 caso 3): la riapertura differita e la consegna 0x81
   condividono il protocollo di pulizia gate;
   `0xCD558(1, 0x442644)` (ret≠0 -> `0x65CDF4`); `0x14A228`,
   `0x65BBD8`, `0x65DAD0`; getter modo ORIGINALE 0xCAD30:
   ==0x7E -> `0x149028(node,9)` + `0x65DDA8(0,0)` (dopo il ramo
   r1:=0); `0x143AFC(0x16/0x15/0x14)`; `0xCE5C8` (ret≠0 ->
   `0x2106F4(1)`); `0x660C34`; `0xAD90C(ret, 0x110)`;
   `bl.d 0x145C3C` con delay slot `ld_s [pool 0x65B1C8=0x7530]`
   -> **0x145C3C(30000)**; `0x145150(node)`; modo 0x2C ->
   `0x14905C(node,1,500,500,0)`, 0x68 ->
   `0x14905C(node,0x13,100,100,0)`; `0xCD8CC` (ret==0 ->
   `0x14905C(node,0xB,250,250,0)`); `0x12845C` (ret≠0 ->
   `0x14905C(node,0xE,400,400,0)`); `0x65CF58(node)`.
5. **Stati altri** (es. 5): solo `0x143AFC(0x16/0x15/0x14)`, nessuna
   scrittura di stato o gate (casi 1, 2, 8).

**Conseguenza AkeruOS**: dopo una chiusura 0x4405 con esito
differito, la transizione di completamento non passa per un nuovo
evento WindowManager ma per la consegna 0x81: la coda AkeruOS deve
considerare che (a) lo 0x100 residuo è annullato da 0x65B060 solo
alla consegna 0x81, (b) il teardown degli stati 2/3 usa lo stesso
raccordo gate dell'handler 0x4405, (c) un ritorno anticipato (gate
d10c4==1 ∧ stato 3) lascia [ctx+0x18] intatto e restituisce lo
stato come valore di ritorno.

**Mappa completa dei writer di [ctx+0x18]** (census statico della
regione ASLV: 6 siti con displacement 0x18, allineamento di
default; il carve it.33 delle 14 entrate disallineate non aggiunge
siti; revisione ex-novo con finestre allineate per funzione:
conferma i 6 siti). Attenzione al controesempio della revisione:
dei 6, **solo 4 scrivono [ctx+0x18] del contesto ASLV
(0x681F74)**:

| Sito | Istruzione | EA effettiva | Contesto |
|---|---|---|---|
| 0x659586 | st_s r13,[r0,0x18] | 0x681F74 | apertura 0x659554: := arg |
| 0x65996A | st_s r1,[r0,0x18] | 0x681F74 | chiusura 0x4405 differita: := 0x100 |
| 0x6599B4 | st_s r15,[r0,0x18] | 0x681F74 | chiusura 0x4405 differita: := 0 |
| 0x65B0B0 | st_s r15,[r14,0x18] | 0x681F74 | handler 0x81 (questo): cancel a 0 |
| 0x65AC0C | stw_s r0,[r13,0x18] | 0x681FB0/B4/B8 | handler 0x7D40 (0x65AB5C), base pool 0x65AC50=0x681F98, loop r14=0..2 |
| 0x65AC18 | stw_s r1,[r13,0x18] | 0x681FB0/B4/B8 | handler 0x7D40 (0x65AB5C), come sopra (ramo di azzeramento) |

I siti 0x65AC0C/0x65AC18 usano r13 caricato da pool 0x65AC50 =
**0x681F98** (0x65ABAC ld_s r13,[pcl,0xa4]; 0x65ABB4 add1_s
r13,r13,r14) — un contesto FRATELLO dell'ASLV, non 0x681F5C: la
mia attribuzione iniziale «handler 0x80, writer di [ctx+0x18]» era
ERRATA ed è stata corretta dopo la revisione (C5). L'handler 0x80
(0x65AC58, record 7) è il callee ri-dispatch del percorso
differito it.30 e NON è un writer di [ctx+0x18] dell'ASLV.

LE di 0x681F74 ([ctx+0x18]) in tutti i blocchi: **zero** — nessun
codice indirizza la cella direttamente, tutto passa per base+disp.
LE di 0x681F5C: esattamente i 20 pool della finestra (blocco 2).
La mappa dei writer dell'[ctx+0x18] ASLV è quindi COMPLETA:
apertura (arg), chiusura differita (0x100/0) e cancellazione
(handler 0x81). Il contesto 0x681F98 (handler 0x7D40) resta
APERTO: è il prossimo anello.

## Fonti e indirizzi

- Blocchi 0/2/3 V1.1; registro p3 0x783B08 (payload 3): 39 record,
  record 8 ev 0x0081 → 0x65B060 (0x783B48/0x783B4C), record
  0x4405 → 0x65959C (sanity).
- Finestre CPU byte-originali: `.mili` 0x334100..0x3341E4,
  `.modeget` 0xCAD30..0xCAD38 + `.modepool` 0xCAAC4 (=0xC8E80C),
  `.poolctx` 0x65AFF8..0x65AFFC (=0x681F5C), `.poolg`
  0x65B00C..0x65B010 (=0x442644), `.b60` 0x65B060..0x65B1CC
  (incluse le pool interne 0x65B1C4=0x3669EC, 0x65B1C8=0x7530).
- Pool congelati: 0x65AFF4=0x00B00100, 0x65AFF8=0x681F5C,
  0x65AFFC=0x02600001, 0x65B00C=0x442644, 0x65B1C4=0x3669EC,
  0x65B1C8=0x7530, 0x65D0E8=0x681F5C (helper).
- Chiamanti bl (census su tutti i blocchi, totale 3):
  0x6599C6 (bl, handler 0x4405 percorso differito, dopo
  `[ctx+4]:=2`, r0=node), 0x65B224 (bl_s, handler 0x100 0x65B1CC,
  dopo `[ctx+4]:=2` gate `[0x47BBC8]>0`, it.28), 0x65D0DE (bl,
  helper 0x65D098). Freeze dei tre siti chiamanti nel verificatore.
- Helper 0x65D098 decodificato (statico + freeze; NON eseguito in
  CPU qui): se `[ctx+4]==6 ∧ guardia(0xCA310)==1` ->
  `0x149028(node,4)` (0x65D0BC), `0x149028(node,0xF)` (0x65D0C4),
  `0x176828(3,0,0x32)` (0x65D0D0), `[ctx+4]:=2` (0x65D0D6),
  `0x65B060(node, 0x81, 1)` (0x65D0DE), `[ctx+0x1C]:=0` (0x65D0E2),
  tail `b 0x659588` nell'epilogo condiviso dell'handler di
  apertura; anche il percorso gate-fallito converge nello stesso
  tail (correzione revisione C4: tre chiamate omissionate nella
  prima stesura).

## Comandi eseguiti ed esiti

- `python3 Python_Trace_Scripts/s33_verify_aslv_b060_arg18_clear_cpu.py`
  → **PASS_ASLV_B060_HANDLER_081 20261101T190743571858Z** +
  riesecuzione identica **20261101T190802453662Z** (9 casi:
  b060_clear_s5, b060_noclear_101, b060_early_s3,
  b060_teardown_s2, b060_teardown_s3_2c, b060_teardown_s2_68,
  b060_teardown_7e, b060_d10c41_s5, b060_teardown_s2_101; fault
  0xDEADB001..09).
- Recupero it.33: rilanciati i censimenti `tmp/it33/census_loaders4.py`
  (64 loader sui 20 pool ctx), `census_stores18.py`,
  `census_twoalign2.py`, `census_all_st18.py` (6 store), tutti
  concordanti con i risultati incorporati nel verificatore.
- Regressioni 8/8 PASS: snapshot record init **185902847062Z**,
  guard setter census **185903622471Z**, service raise pending
  **185914Z**, wm notify registry **185919051518Z**, notify
  reactors **185921854665Z**, aslv slot handlers **185928361135Z**,
  aslv open wrapper **185948839763Z**, aslv close handler
  **190010031532Z**.

## Fixture e assunzioni

Contesto 0x681F5C fixture 0xD0 byte (sentinelle 0xA5): word stato
a +4, [ctx+0x18] word per caso, avanzi apertura +8=0xFF/+9=0x5A,
[ctx+0x24] sentinella. Cella modo 0xC8E80C per caso (0x2B/0x2C/
0x68/0x7E). Gate: [0x442734] sentinella, [0x3669EC]=0x368000
(puntatore fixture), [0x3680F0] sentinella. ~25 callee STUB
(registrano {sid, r0, r1, r2}, ritorni imposti per caso); originali
eseguiti: corpo .b60, millicode, getter modo 0xCAD30. Chiamata
d'ingresso con (node, 0x81, 1) come nell'helper 0x65D098; il corpo
ignora r1/r2 dopo il prologo. Assunzione NON verificata: significato
runtime degli stati 2/3/5, dell'evento 0x81 e dei servizi.

## Controlli negativi

- Cancellazione SOLO a 0x100: casi 2 (0x101 intatto) e 9 (teardown
  con 0x101: [ctx+0x18] resta 0x101, nessuna 0xCB5B0) — il teardown
  non scrive mai [ctx+0x18].
- Gate d10c4==1 da solo NON blocca (caso 8, stato 5); blocca SOLO
  con stato 3 (caso 3: nessuna chiamata dopo D10C4, [ctx+0x18]
  resta 0x100, celle gate e [ctx+0x1E] intatte).
- CD558 ret 0 -> nessuna 0x65CDF4 (caso 5); CD8CC ret 1 -> nessuna
  0x14905C(0xB) (caso 6); 12845C ret 0 -> nessuna
  0x14905C(0xE) (casi 4, 5, 7, 9); 148E68 ret 1 -> nessuna
  0x148E14 (tutti tranne caso 2).
- Stati altri del teardown: casi 1/2/8 non toccano [ctx+4],
  [ctx+0x1E], [ctx+0x1D], celle gate; assert «nessuna chiamata
  oltre il conteggio atteso» in ogni caso.
- LE di [ctx+0x18] diretta: zero in tutti i blocchi (controllo
  statico negativo).

## Limiti e non dimostrato

Statica + 9 casi CPU con fixture: nessun hardware/boot/rendering/
scatto/persistenza; NON_INSTALLARE; ~10% invariato. ~25 callee
STUB: comportamento reale non provato qui. L'helper 0x65D098 è
decodificato e congelato ma NON eseguito in CPU (prossimo passo
naturale). Il contesto fratello 0x681F98 (handler 0x7D40
0x65AB5C, writer halfword 0x65AC0C/0x65AC18 a 0x681FB0/B4/B8) e
l'handler 0x80 (0x65AC58, callee ri-dispatch del percorso
differito it.30) sono APERTI: non decodificati qui. Produttori RUNTIME di cfg[1]/[2], delle celle
notifica 0x366AF0/0x366AF1, del timer [0x682020] e della cella
[0x47BBC8] (gate dell'handler 0x100): APERTI. Concorrenza,
schedulazione e ordine runtime 0x4401/0x4405/0x4406/0x81 NON
provati. V1.1 vs V1.0 non confrontato. Il valore di ritorno nei
percorsi non anticipati è r0 = ritorno dell'ultima chiamata
(0x65CF58 o 0x143AFC(0x14)) — non semanticamente identificato.

## Agenti e revisione indipendente

**Agente `b060-review-34`** (tools.agents.spawn, atteso e
integrato; il tool «task con agente explore» non esiste, usato
agents.spawn come nelle iterazioni precedenti): revisione statica
ex-novo con objdump proprio, census propri su tutti i 16 blocchi +
payload TBIB/TBM/P1RES, scan LE a ogni offset. Esito:
- **C1 CONFERMATO** (record 8 del registro p3; 3 chiamanti; unica LE
  0x783B4C; l'hit nel payload TBM integro a file_off 0x4FA74C è lo
  stesso record, delta 0x400 = header contenitore).
- **C2 CONFERMATO** sito per sito; precisazione: r1/r2 passati
  VIVI a 0x17083C dopo il save in r17/r16 (le copie non sono mai
  lette).
- **C3 CONFERMATO** (5 pool sui byte grezzi).
- **C4 PARZIALE**: tre chiamate omissionate nell'helper 0x65D098
  (0x149028(node,4) @0x65D0BC, 0x149028(node,0xF) @0x65D0C4,
  0x176828(3,0,0x32) @0x65D0D0) — INTEGRATE (riverificate da me
  sul listato).
- **C5 PARZIALE con controesempio**: i siti 0x65AC0C/0x65AC18
  appartengono all'handler 0x7D40 (0x65AB5C) e con base pool
  0x65AC50=0x681F98 scrivono 0x681FB0/B4/B8, NON [ctx+0x18]
  dell'ASLV — attribuzione ERRATA nella mia prima stesura,
  INTEGRATA (riverificata da me byte-esatto: 0x65ABAC/0x65ABB4)
  e riesecuzione del verificatore con nota corretta.
- **C6**: nessun altro writer delle celle gate nel corpo; zero usi
  di r16/r17 dopo il save; nessun ramo tralasciato (13 branch +
  tail); valori di ritorno confermati (teardown -> ret(0x65CF58),
  altri stati -> ret(0x143AFC(0x14)), anticipato -> [ctx+4]).
- Nota strumentale: con binutils 2.45 di sistema la ricetta objcopy
  indicata lascia la VMA a 0 (ordine dei flag) e `-M arc700` non è
  riconosciuto; la toolchain del progetto (work/build-arc) funziona
  ed e' quella usata dal verificatore.
Appunti in /tmp/rev34/ (sessione). PMB outbox 393.

## Prossimo passo

(a) **CPU dell'helper 0x65D098** (stato 6 ∧ guardia 1 -> stato 2 +
consegna 0x81 cortocircuitata): chiude il ciclo stato6→0x81 e
riutilizza le finestre/stub di questo verificatore. (b) In
alternativa: decodifica del contesto fratello **0x681F98**
(handler 0x7D40 0x65AB5C, record 6; writer 0x681FB0/B4/B8) per
capire la famiglia di contesti della finestra. (c) In alternativa:
writer 0x65B212/0x65B2EA dell'handler 0x100 (stati 2/6, gate
[0x47BBC8]) già parzialmente noti da it.28.
