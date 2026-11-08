# Router 0x169F60 su tabelle finestra e registro globale: catena nidificata p5→default→wrapper→p1 provata in CPU, lista di esclusione 0x99ACAC identificata, census 228 chiamanti — 1° novembre 2026 (iterazione 21 della richiesta; replica indipendente del punto it.46(a), chiuso anche dalla sessione interrotta it.47)

## Contesto e domanda

Il checkpoint indicava come aperto il consumatore del registro notifiche p1
(it.46(a)). Durante questa iterazione è emerso che una sessione precedente
interrotta lo aveva già chiuso senza propagarlo ai checkpoint:
[S33_GUI_Registro_Notifiche_Consumatore_CPU_20261101.md](S33_GUI_Registro_Notifiche_Consumatore_CPU_20261101.md)
(verificatore `s33_verify_registry_consumer_cpu.py` PASS 20261101T144258994696Z
+ riesecuzione identica, 13 casi CPU, mappa 66 voci). Questa iterazione ha
riscoperto indipendentemente lo stesso consumatore partendo dai candidati del
checkpoint (installer 0x145010/0x145018, resolver 0x14505C) e lo ha esteso.
Esito: **replica indipendente con convergenza completa + quattro estensioni
nuove**, documentate qui.

## Verificatore (nuovo)

`Python_Trace_Scripts/s33_verify_wm_notify_registry_cpu.py` →
**PASS_WM_NOTIFY_REGISTRY 20261101T155229008610Z** (corsa di riferimento,
docstring con indici R57/R58 corretti dall'audit) + riesecuzioni PASS e
identiche salvo `utc`: **154903181063Z**, **154909405237Z**, **154932736078Z**.
Prove: `Risultati/GUI_S33/wm_notify_registry_cpu_20261101T155229008610Z/`
(10× .s/.ld/.elf + sezioni .bin byte-identiche ai payload + verified_evidence.json).

Finestre ORIGINALI per tutti i casi: router 0x169F60..0x169FB4, wrapper
0x20E814..0x20E848 (pool 0x20E844), millicode 0x334120..0x33413A /
0x33418C..0x3341E4, registro p1 0x3E8BB4..0x3E8DD4, tabella p5
0x99AB8C..0x99ACD0. Stub SOLO agli indirizzi dei reattori raggiunti.

## Risultato 1 — replica indipendente del consumatore (convergenza con it.47)

- **Router 0x169F60(r0, r1=tabella, r2=nodo, r3=evento, r4=arg)**:
  push blink + millicode 0x334130 (push r14,r13); r14=tabella, r13=nodo,
  r1=evento, r2=arg. Se r0≠0: r0 punta a un array **u16** di eventi da
  escludere (stride 2, terminatore 0); se l'evento è nella lista → **ritorno
  0 senza dispatch**. Scansione con stride 8: **evento halfword a +0
  (`ldw_s.x`), pad halfword a +2 (mai letto), handler u32 a +4 (`ld`)**;
  prima corrispondenza → `jl_s.d [r3]` con delay slot `mov r0,r13` →
  handler(nodo, evento, arg). Record con evento==0 senza corrispondenza:
  handler caricato e chiamato se non nullo (**default**), altrimenti
  ritorno 0. Epilogo 0x33419C (pop r14,r13,blink).
- **Wrapper 0x20E814(nodo, evento, arg)**: pool **0x20E844 = 0x3E8BB4**,
  UNICA parola 4-allineata con quel valore in tutti i 16 payload (LE scan
  a ogni allineamento confermato dall'audit); chiama
  `0x169F60(0, 0x3E8BB4, nodo, evento, arg)` (prologo 0x33412C, epilogo
  0x334194).
- **Registro p1: base 0x3E8BB4, 66 record di evento + terminatore {0,0} a
  0x3E8DC4**. Precisazione rispetto a it.47 («{u32 evento, u32 handler}»):
  il router legge il campo evento come **halfword** a +0; con i dati reali
  (eventi < 0x10000, pad sempre 0) le due letture coincidono. **NESSUN
  record default**: il terminatore è null-null, quindi un evento non
  abbinato del registro globale ritorna 0 (il ramo default del router
  esiste ma su questa tabella resta inattivo).
- **Correzioni it.46 confermate in CPU**: 0x4410→**0x20E848**,
  0x4005→**0x20F294**, 0x4006→**0x20F414** (R57/R58 dopo audit: gli indici
  R63/R64 del claim iniziale del coordinatore erano slittati di 6),
  0x0080→0x20E940, 0x7CE4→0x20E900 (R0), 0x4001→0x20EF00, 0x410A→0x20FF9C,
  0x3281→0x1443C0, 0x3301→0x1449C4, 0x4124→0x210364, 0x2180→0x20E940.
  Nessun evento duplicato; tutti gli handler in codice p0
  [0x0AD800, 0x35BC00).
- Casi CPU 1-8: ev4410, ev4006, ev7ce4 (registro reale, dispatch con
  (nodo, evento, arg) loggati dallo stub), unmatched (ritorno 0),
  excl_hit/excl_miss (lista sintetica), null_handler (tabella sintetica,
  handler 0 → ritorno 0), wrapper (ingresso 0x20E814 → stesso dispatch).

## Risultato 2 — tabella finestra p5 e catena nidificata (NUOVO)

- **p5 0x99AB8C** (tabella della finestra ponte it.43): 35 record di evento
  + **R35 default {0x0000, 0x20E814}** (36 record totali), stesso layout del
  router. Il default è il wrapper: gli eventi non gestiti dalla finestra
  vengono inoltrati ORIGINALE-compresi al registro globale.
- **Caso CPU p5_ev3b81**: `0x169F60(0, 0x99AB8C, nodo, 0x3B81, arg)` →
  stub a **0x7F8674** riceve (nodo, 0x3B81, arg) — il contesto ponte
  0x3B81 di it.43 è ora una route del router.
- **Caso CPU p5_default_to_global**: evento 0x7CE4 (assente dalla tabella
  p5) → R35 default → **wrapper ORIGINALE eseguito** → seconda invocazione
  del router sul registro globale → R0 → stub **0x20E900** riceve
  (nodo, 0x7CE4, arg). Catena completa
  **tabella finestra → default → wrapper → registro globale → reattore**
  in CPU con byte originali, 350 istruzioni, due invocazioni annidate del
  router con stack bilanciato. Il registro p1 NON ha default, quindi la
  catena si arresta lì se anche il registro manca l'evento (caso
  `unmatched`).

## Risultato 3 — lista di esclusione 0x99ACAC e callback 0x7F6824 (NUOVO)

- **Array u16 a 0x99ACAC** (subito dopo la tabella p5): 0480 0481 0500
  0501 0380 0381 0400 0401 0580 0700 2180 2700 0581 0701 2181 2701
  **4004** 0000 — 17 voci + terminatore. È la **lista di esclusione**
  del router: i quattro slot pulsante logici (0x580/0x581, 0x700/0x701,
  0x2180/0x2181, 0x2700/0x2701) più 0x480/0x500/0x380/0x400 e 0x4004.
- **CPU**: con la lista {0x4410,0} l'evento 0x4410 NON viene consegnato
  (ritorno 0); con {0x9999,0} la consegna avviene (casi excl_hit/excl_miss).
- **Audit statico del callback finestra 0x7F6824** (it.43/45): gate
  `[0x80, 0x307F]` (cmp a 0x7F685C/0x7F6864); gli eventi FUORI range
  vanno a `0x169F60(r0=0x99ACAC esclusione, r1=0x99AB8C tabella, nodo,
  evento, arg)` (pool p4 0x7F6A48=0x99ACAC, 0x7F6A4C=0x99AB8C, chiamata a
  0x7F6A1C). Conseguenza: gli slot pulsante in-range sono gestiti dal
  callback stesso; gli eventi di sistema fuori range nella lista (es.
  0x4004) NON passano dalla tabella finestra.
- **Wrapper gemello 0x224AB8** (controesempio C6c dell'audit): stessa
  forma del C3, pool 0x224AE8 = **0x3EB554 (tabella in p1)** con
  {0x7CC2→0x224F4C, 0x7CC5→0x224DD8, 0x4004→0x224AEC, default
  {0,0x20E814}}: anche i suoi eventi non gestiti finiscono nel registro
  globale.

## Risultato 4 — census 228 chiamanti del router (estende it.47 risultato 2)

- **228 chiamanti `bl` a 0x169F60** nel listato GNU (confermato
  indipendentemente dal coordinatore e dall'audit): **p0:36, p2:29,
  p4:143, p6:20**. L'audit ha classificato TUTTI i 228 siti: in 228/228
  r1 proviene da `ld_s r1,[pcl,imm]` (pool PC-relativo) e il valore di pool
  punta a una tabella {u16,u16,u32} strutturalmente valida con terminatore;
  228 tabelle distinte, una per chiamante. Distribuzione: **p0→tabelle
  p1, p2→p3, p4→p5, p6→p7**.
- **202/228 siti passano r0≠0**; 193 puntano a liste di esclusione valide
  (es. 0x134D90→0x38FE58: 0300 0301 0280 0281 0780 0800 4110 4111 0000);
  9 casi degeneri (lista vuota con primo halfword 0, o r0 da registro,
  es. 0x659536 `mov_s r0,r13`) — non controesempi alla semantica.
- **182 parole LE 4-allineate 0x20E814** in dati descrittori (p1:20,
  p3:7, p5:135, p7:20; NESSUNA in p0/p2/p4) — slot handler di record
  default: altrettante tabelle finestra inoltrano al registro globale
  (convergenza con it.47 risultato 2; l'audit le ha ricondotte tutte a
  record {ev=0, pad=0, handler=0x20E814}).

## Audit indipendente (agente `registry-audit-21`)

Revisione statica in sola lettura con metodo proprio (byte dai payload
verificati, listato GNU, nessuna esecuzione del verificatore nuovo):

- **C1 CONFERMATO** (semantica router byte-esatta, inclusi push/pop
  millicode 0x334130/0x33419C e delay slot).
- **C2 PARZIALE**: base 0x3E8BB4, 67 slot e accoppiamenti CORRETTI
  confermati; due correzioni al claim del coordinatore, già applicate:
  indici R57/R58 (non R63/R64) per 0x4005/0x4006, e **nessun default in
  p1** (R65={0x4124,0x210364} è un record di evento; il terminatore
  R66 è null-null).
- **C3 CONFERMATO** (wrapper, pool unico).
- **C4 CONFERMATO** (tabella p5 con default R35={0,0x20E814}; conteggio
  36 record = 35 evento + 1 default; array 0x99ACAC = 18 halfword).
- **C5 CONFERMATO** (228 bl, tutti 32-bit, zero bl_s; classificazione
  completa).
- **C6**: (a) nessun controesempio (66/66 pad=0, handler in range);
  (b) nessuna seconda occorrenza di 0x3E8BB4; (c) controesempi positivi
  accolti: wrapper gemello 0x224AB8→0x3EB554 e 182 slot default;
  (d) r0≠0 è la norma (202/228), callback 0x7F6824 decodificato con
  range [0x80,0x307F] e chiamata (0x99ACAC, 0x99AB8C, nodo, evento, arg).

Esito registrato dall'agente in PMB (record_batch, 2026-11-01).

## Comandi/esiti

```
python3 Python_Trace_Scripts/s33_verify_wm_notify_registry_cpu.py
  → PASS_WM_NOTIFY_REGISTRY 20261101T155229008610Z
    (+ identiche 154903181063Z / 154909405237Z / 154932736078Z)
python3 Python_Trace_Scripts/s33_verify_wm_service_dispatch_cpu.py    → PASS 154912169644Z (it.46)
python3 Python_Trace_Scripts/s33_verify_wm_current_switcher_cpu.py    → PASS 154917531798Z (it.18/47)
python3 Python_Trace_Scripts/s33_verify_capture_guard_setter_census.py → PASS 154935478062Z
python3 Python_Trace_Scripts/s33_verify_service_raise_pending.py     → PASS 154947Z
python3 Python_Trace_Scripts/s33_verify_event_router_producers_cpu.py → PASS 154951182708Z
```

Correzioni di banco durante lo sviluppo (documentate, asserzioni non
indebolite): slice delle assert byte (12/26 byte); probe spostata da
0x169F00 a 0x169000 (collisione con la finestra router); salto alla probe
aggiunto nell'harness dopo il ritorno del router; finestra wrapper mancante
nel caso nidificato (timeout del sim su memoria non mappata → aggiunta);
REG1_OLD_BYTES 0x3E8DC8→0x3E8DC0; ordine EXCL_IDS ricavato dai byte;
census per-payload parsato dal token V del listato (non dall'offset file).

## Fonti precise

- Payload0 (base 0x0AD800): router 0x169F60..0x169FB4, wrapper
  0x20E814..0x20E848 (pool 0x20E844=0x3E8BB4), wrapper gemello
  0x224AB8 (pool 0x224AE8=0x3EB554), millicode 0x334120..0x33413A /
  0x33418C..0x3341E4, callback finestra 0x7F6824 (gate 0x7F685C/0x7F6864,
  chiamata 0x7F6A10..0x7F6A1C, pool p4 0x7F6A48/0x7F6A4C), reattori
  0x20E848/0x20E900/0x20E940/0x20F294/0x20F414/0x20FF9C/0x210364/0x7F8674.
- Payload1: registro 0x3E8BB4..0x3E8DD4 (66+terminatore), tabelle
  p0-chiamanti (es. 0x38FE58/0x38FE6C), tabella 0x3EB554, 20 slot default.
- Payload3: 7 slot default; p5: tabella 0x99AB8C..0x99ACB4 + array
  0x99ACAC..0x99ACD0, 135 slot default; p7: 20 slot default.
- Evidenze: `Risultati/GUI_S33/wm_notify_registry_cpu_*` (4 run), più le
  regressioni elencate nei comandi.

## Limiti

- Statico + 10 casi CPU sintetici: nessun hardware, boot, rendering,
  scatto o persistenza; NON_INSTALLARE; **circa 10% invariato**.
- La tabella p5 è eseguita solo sulle due route provate (0x3B81 e default
  → 0x7CE4); gli altri 33 handler p5 e i reattori del registro sono
  STUB, non eseguiti.
- Il callback 0x7F6824 è decodificato solo STATICAMENTE (audit): il gate
  [0x80,0x307F] e la chiamata con lista di esclusione NON sono stati
  eseguiti in CPU.
- Il reattore 0x20F414 (0x4006 corretto) resta da decodificare; idem gli
  altri reattori della mappa corretta.
- Census da listato GNU (scansione lineare): chiamate indirette jl non
  contate; regioni dati decodificate come codice possono dare falsi
  positivi (ogni sito classificato è comunque in range codice).
- Schedulazione runtime (chi produce 0x7CE4/0x4006, quando) NON provata.
- V1.1 campione vs macchina V1.0; non trasferire indirizzi fra versioni.

## Prossimo passo (non ripetitivo)

(a) **Decodificare e provare in CPU il reattore 0x20F414 (evento 0x4006
    corretto)** e i reattori degli slot pulsante nella mappa del registro
    (0x700→0x20EAF4, 0x2180→0x20E940, 0x580/0x2700): ora che
    evento→reattore è CPU-provato si può chiudere
    snapshot→coda→dispatcher→finestra→callback→router→reattore per gli
    slot logici (proposta già in it.47, ancora valida).
(b) **CPU del callback finestra 0x7F6824** con lista di esclusione
    0x99ACAC e tabella 0x99AB8C: tre percorsi (evento in-range gestito
    direttamente, out-of-range escluso dalla lista, out-of-range inoltrato
    alla tabella/default) — collega il gate it.45 con la consegna it.43 e
    chiude il ruolo runtime della lista di esclusione.
