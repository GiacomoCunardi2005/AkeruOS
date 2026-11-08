# CaptureMenu: censimento dei 63 chiamanti della transizione di modalità 0xCA404, cella "modalità desiderata" 0x3657C8 e reachability/CPU della switch guardia 0xCBC00 — 1 novembre 2026 (iterazione 41)

## Domanda

Prossimo passo (a)+(b) dell'iterazione 40: censire i 63 chiamanti `bl` della funzione di transizione della modalità di scatto `0xCA404` e classificare l'argomento (r0 = nuova modalità) passato in ogni sito — in particolare chi può portare la cella modalità `0xC8E80C` a/da `0x2C` — e stabilire la reachability statica della switch della guardia `0xCBC00`, che l'iterazione 40 aveva lasciato «indeterminata».

## Verificatore ed esiti

- Script: `Python_Trace_Scripts/s33_verify_capture_transition_caller_census.py` (statico + 7 casi CPU con byte firmware originali).
- Esiti, tutti exit 0, senza pipe:
  - `python3 Python_Trace_Scripts/s33_verify_capture_transition_caller_census.py` → **PASS_CAPTURE_TRANSITION_CALLER_CENSUS 20261101T114158737678Z**; riesecuzione indipendente → **PASS_CAPTURE_TRANSITION_CALLER_CENSUS 20261101T114219085464Z** (classificazione e casi byte-identici; differiscono solo utc e hash dei `.command.json` con percorsi auto-referenziali); dopo l'audit (docstring 0x8022B8 corretta, gate 0x7CB62E esteso) → **PASS_CAPTURE_TRANSITION_CALLER_CENSUS 20261101T115840936113Z**.
  - [Evidenze](../Risultati/GUI_S33/capture_transition_caller_census_cpu_20261101T115840936113Z/) (versione finale post-audit, `verified_evidence.json`, `static_evidence.json`, 7 sotto-directory dei casi CPU con ELF, assembler, linker script, log); [prima esecuzione](../Risultati/GUI_S33/capture_transition_caller_census_cpu_20261101T114158737678Z/), [riesecuzione](../Risultati/GUI_S33/capture_transition_caller_census_cpu_20261101T114219085464Z/) (identiche nelle asserzioni; la 114158Z e la 114219Z portavano la docstring poi corretta).
- Regressioni rieseguite tutte PASS: guard setter census **20261101T114226104068Z**, flag mode matrix 14 casi **20261101T114238025825Z**, snapshot record init 4 casi **20261101T114238521591Z**, service raise pending **20261101T114239Z**.

## Risultato 1 — census e classificazione dei 63 chiamanti di 0xCA404

Census su listing GNU (`Risultati/Disassemblati/Firmware1.1.asm`, regex bl/bl.d/bl_s/bl_s.d): **esattamente 63** chiamanti — payload0: 15, payload2: 10, payload4: 38 — lista congelata nello script; ogni sito è verificato con finestra disassemblata allineata byte-esatta e con la proprietà «nessuna istruzione che scriva r0 fra il produttore dell'argomento e la chiamata».

Classificazione dell'argomento r0 (conteggi congelati, somma 63):

| classe | siti | significato |
|---|---|---|
| `const_2c` + `const_2c_event_gated` | 7 + 1 | portano **a 0x2C**: p0 0xC9FDA, 0xD236E, 0x1360DA, 0x1E132C; p2 0x65C670; p4 0x7D4F58, 0x80D45C, 0x8022B8 |
| `const3` | 8 | 0x651186, 0x656032, 0x65C3DA (p2); 0x7F6AF0, 0x7FDA1C, 0x802204, 0x802248, 0x80D43C (p4) — modo 3: `0xCA404` **non azzera la guardia** in questo caso |
| `const4` | 7 | 0xC39E8; 0x64AB8C, 0x64ABA2, 0x6513F0, 0x651CA0, 0x651DDE; 0x80D44C |
| `const_0a` | 3 | 0x2C4FD4 (helper pannello iride), 0x7D4EF8, 0x7D4F38 |
| `const_21/6f/70` | 1+1+1 | 0x664C6A, 0x7CAF6A, 0x7CAF9C |
| `mode_getter_refresh` | 2 | 0xBBA88, 0x20F1D2: passano l'output del getter `0xCAD30` = modalità corrente → change-detection, early-exit (refresh no-op salvo cambio concorrente) |
| `desired_cell_d0528` | 15 | passano il byte della cella **0x3657C8** letto dal getter `0xD0528` chiamato immediatamente prima (v. Risultato 2) |
| `struct_a_byte`/`gated_0x15`/`gated_ne_current` | 2+2+1 | 0x7CA790, 0x7CA836, 0x7CA73A, 0x7CA7E0, 0x7CA896: byte [r14,0xA] del contesto CaptureMenu (0x15 = modo già confrontato dal gate) |
| `struct_3way_899844` | 1 | 0x7CAED0: [0x899844+0x11] se [+0x12]≠0 altrimenti [+0x10] |
| `arg_r14` | 6 | 0x322BA0/0x322C34/0x322CD8, 0x80E388/0x80E41C/0x80E4C0: argomento r1 della funzione contenente |
| `struct_neg222` | 1 | 0xD2434: `ldb r0,[r14,-222]` gate [r14,-221]==0 |
| `struct_367a34_plus8` | 2 | 0x1747B6, 0x1747CA: `ldb_s r0,[r1,0x8]` gate [r1,0x1e]==1; pool reale **0x174564 = 0x367A34** (ld.as scalate a PC 2 mod 4; i commenti objdump ;0x174717/;0x174726 non scalati NON vanno usati). Il byte letto ha un solo writer statico adiacente (0x174794–0x17479C, stesso pool 0x174564) che scrive **0xA o 0x4** |
| `r13_gated` / `extb_r13` | 1+1 | 0x7CB62E (r13 ∉ {[r13,9], 0x15, 0x1F, 0x79, 0x7B, 0x6E}; gate completo post-audit: `ldb_s r1,[r13,0x9]`/`extb_s r13,r0`/`cmp r1,r13` a 0x7CB610–0x7CB616 e `cmp_s r13,0x15` a 0x7CB618), 0x80C4AA |

Il sito **0x8022B8** è un dispatcher sull'ID evento r13 (correzione post-audit, v. sezione Audit): i tre ID evento dei pulsanti logici GUI `cmp r13,1792` (0x700), `cmp_s r13,0x2180`, `cmp_s r13,0x2700` **deviano su altri handler** (`jl_s [r2]` a 0x8022C2/0x8022C8/0x8022CE); la chiamata a 0xCA404 avviene per gli **altri** ID evento, e solo se la modalità corrente **non** è 0x2C (getter 0xCAD30 + `cmp 0x2C` + skip), dopo `bl 0xCBDF8` e `bl 0x177030`: ritorna la fotocamera a 0x2C. È un gate statico verificato, non una mappa fisica dei tasti.

Il sito **0x1360DA** è gate su «modalità corrente == 0x2C ∧ [r13,41]==0» e prima della chiamata esegue `0xCD89C(0)` (setter byte [0xC8EB18]) e `0xC9D58→0xC9D84(3,1)` (reset di contesto che confluisce nel teardown 0xC9DB6: guardia=0 a 0xC9DEA e flag=0 a 0xC9DF0): con corrente==0x2C la transizione passata è refresh; se `0xC9D84` modifies la cella modalità il valore resta APERTO (non decodificato in questa iterazione).

## Risultato 2 — cella 0x3657C8: «modalità desiderata» della stessa struct della guardia

`0xD0528` è un getter di tre istruzioni (`ld_s r0,[pcl,0x8]` → pool **0xD0530 = 0x3657C8**; `ldb_s r0,[r0,0]`; `j_s [blink]`). Verificato:

- `0x3657C8` = struct **0x365750 + 0x78**: la stessa struct che contiene la guardia a +1 (0x365751) e il flag di guardia salvata a +188 (0x36580C).
- **Un solo** pool word `0x3657C8` in tutti i 16 payload (LE scan congelato: {0: [0xD0530]}).
- Byte statico nell'immagine payload1: **0x2C**, uguale al valore di boot della cella modalità 0xC8E80C (record TBIB 8+0xC).
- Census: **21** chiamanti bl di 0xD0528 (3 in p0 + 18 in p4); **15** sono i produttori immediati di una chiamata a 0xCA404 (i restanti 6: 0x252C0E, 0x25327A, 0x7F6AF4, 0x7F8ACC, 0x7FAA50, 0x7FBE3A usano il valore in altro modo). Il corpo è di 3 istruzioni più un `nop_s` di riempimento a 0xD052E; le parole adiacenti (0xD052C, 0xD0538) sono codice, non puntatori (audit C3).
- Nessuno store né load `[rN,120]` entro le finestre limitate (48 byte) dei **25** siti che caricano i 14 pool della struct 0x365750 (stesse finestre del censimento +188 dell'iterazione 40): **nessuno scrittore statico diretto identificato**. L'audit ha esteso la scansione a tutti i 31 riferimenti statici ai 14 pool (inclusi quelli fuori finestra) con raggio ±512 byte: nessuna occorrenza `[rN,120]` pertinente su tutto il listing. Limite esplicito: writer via aritmetica di puntatore o copia bulk della struct non esclusi da analisi statica.

Interpretazione (ipotesi, non prova): cella «modalità desiderata/ultima modalità di scatto» con valore di boot 0x2C, letta dai 15 feeder per ritornare alla modalità di scatto. Il produttore runtime resta APERTO.

## Risultato 3 — CORREZIONE it.40: la switch 0xCBC00 ha due chiamanti statici ed è un trasformatore di stato della guardia

L'iterazione 40 lasciò la reachability di 0xCBC00 «indeterminata; nessun chiamante statico trovato». Il census completo del listing mostra **esattamente due** chiamanti `bl`, entrambi in payload2, e in **entrambi** l'istruzione immediatamente precedente è `bl 0xca310` (getter guardia): la switch riceve **la guardia corrente** come argomento.

- **0x660B8C** (funzione 0x660B40+), gate corretto post-audit: la switch è chiamata quando `bl 0xce238` ritorna 4 (`cmp r0,4; beq→0x660B88`) **oppure quando [0x681FF0+0x13] != 0** (`ldb_s r0,[r0,0x13]; cmp_s r0,0; bne→0x660B88`); il ramo di modalità (getter ×2, confronti 0x7A/0x7B, `bl 0x15b024` a 0x660B80) **non** chiama la switch: esce via 0x660B84 (`mov r0,3; b→0x660B5A`). Dopo la switch il codice rilegge la modalità e la confronta con 0x2C/0xA.
- **0x663220**: gate: modalità ∉ {0x38,0x39}, `[0x682098+1] != 0`; dopo la switch: getter guardia e confronto con 4, quindi dispatch.

Corpo byte-identico (finestra congelata 0xCBC00..0xCBC3B): prologo, `cmp_s r0,0x4` + `bhi_s` (nessuna scrittura se r0>4), `add r12,pcl,0x10` (tabella 0xCBC1C), `ldb.x r11,[r12,r0]`, pool 0xCBC38=0x365750, `add1 r12,r12,r11` (shift ×2), `j_s [r12]`; tabella `[03,03,03,06,03]` → target 0xCBC22 (`mov_s r1,0`; `stb_s r1,[r2,1]` a 0xCBC24) per r0∈{0,1,2,4} e 0xCBC28 (`mov_s r1,4`; store a 0xCBC2A) per r0=3.

Quindi la switch è il **trasformatore di stato della guardia**: 3→4, {0,1,2,4}→0, >4 invariata. Combinata con i due siti setter `const3_if_guard_4` dell'iterazione 40 (guardia 4→3 a 0x653E02/0x654E84), il ciclo 3↔4 e l'azzeramento diventano percorsi statici identificati in payload2 (AutoScene/CaptureMenu). «Unico produttore statico di guard=7 = restore 0xCA4BE» dell'iterazione 40 resta CONFERMATO: la switch scrive solo 0 o 4.

Il falso riferimento `;0xcbc00e` (riga V00CB7EE8 del listing) NON riguarda la switch: 0xCBC00E appartiene a payload9 (0xC8F800..0xF1FE00), la switch sta in payload0; 0xCB7EE8 è in una regione dati di p9 decodificata per coincidenza. Inoltre tutte le occorrenze LE della word 0xCBC00 nei payload sono **disallineate** (≡3 mod 4): p0 0x355F2B, 0x356D5B; p11 0x1046A3B, 0x1052C0B, 0x1059663, 0x105C687, 0x106380F, 0x106D9DF, 0x1087A5B → nessuna entry di jump-table/puntatore individuata.

## Risultato 4 — CPU: la switch ORIGINALE eseguita in simulatore GNU ARC700

Sette casi con i **byte firmware originali** 0xCBC00..0xCBC3B in un PT_LOAD a 0xCBC00 (verificato in roundtrip sull'ELF), segmento guardia scrivibile a 0x365750 (sentinelle 0xA5, guardia iniziale sentinella) e stack a 0x365900. Nota tecnica del banco: il simulatore esige una sezione `.stack` con VMA sopra tutte le altre (`init_stack`: `prog_end > stack_start` → regione di memoria nulla, errore «sim_core_map_attach with size zero»); banco collaudato prima della stesura definitiva.

| caso | r0 | esito | fault | istruzioni |
|---|---|---|---|---|
| switch_r0_0/1/2 | 0,1,2 | guardia → 0 | 0xdead0000 | 19 |
| switch_r0_3 | 3 | guardia → 4 | 0xdead0004 | 18 |
| switch_r0_4 | 4 | guardia → 0 | 0xdead0000 | 19 |
| switch_r0_5_bhi | 5 | nessuna scrittura, sentinella 0x37 conservata | 0xdead0037 | 11 |
| switch_neighbors | 3 | guardia 4, byte +0/+2 intatti | 0xdead0004 | 28 |

## Fonti precise

Payload0 (base 0x0AD800): transizione 0xCA404 (già it.40), chiamanti per sito in tabella S[] dello script, getter 0xD0528 (pool 0xD0530), getter 0xCA310/setter 0xCA2F4 (it.40), switch 0xCBC00..0xCBC3B (pool 0xCBC38), sito event-gated 0x8022B8, reset 0xC9D58→0xC9D84 e setter 0xCD89C ([0xC8EB18], pool 0xCD8B4). Payload1 (base 0x360800): struct 0x365750..0x365850, byte statico 0x3657C8=0x2C. Payload2 (base 0x5FE800): chiamanti switch 0x660B8C (gate struct pool 0x660BEC=0x681FF0) e 0x663220 (pool 0x663320=0x682098), siti setter guardia 0x653E02/0x654E84 (it.40). Payload4 (base 0x796800): 38 chiamanti, 3-vie 0x7CAED0 (pool 0x7CAE9C=0x899844), event gate 1792/0x2180/0x2700 a 0x80228E..0x8022B6. Payload9 (base 0xC8F800): falso riferimento 0xCB7EE8→0xCBC00E.

## Limiti

Statico + 7 casi CPU sintetici (pool propri con encoding originali; per la switch i byte SONO originali); argomenti calcolati ([r14,0xA], r14/r13, [r14,-222]) non circoscritti a un insieme di valori — [0x367A34+8] ha invece candidati {0xA, 0x4} dall'unico writer statico adiacente, senza escludere writer runtime; writer di 0x3657C8 via aritmetica di puntatore o copia bulk non esclusi staticamente (l'estensione ±512 byte dell'audit copre i 31 riferimenti ai pool, non ogni forma di accesso); jump indiretti con indirizzo calcolato a runtime non coperti; il significato fisico dei modi (0x2C = modalità di scatto è l'interpretazione coerente con it.39/40, non un'etichetta Nikon verificata); i gate su valori restituiti da funzioni non decodificate (0xce238, 0x15b024, 0xc9d84) sono documentati, non decodificati; reachability runtime (scheduler, WindowManager, eventi reali) NON dimostrata; V1.1 campione vs macchina V1.0. Nessun hardware, NON_INSTALLARE, circa 10% invariato.

## Audit

Agente `transition-audit-43` (tools.agents.spawn, revisione statica indipendente; script propri solo in /tmp; `verified_payloads` con SHA verificate e ridisassemblaggio ex-novo di tutti i 16 payload alla rispettiva base; mai toccato firmware, dump, script o evidenze). Verdetto: **C1–C7 CONFERMATI, C8 nessun controesempio reale**, con correzioni di documentazione integrate sopra e nel verificatore (docstring del sito 0x8022B8 invertita, gate 0x660B8C con condizione byte invertita e ramo 0x15b024 non abilitante, gate 0x7CB62E completato con [r13,9]/0x15, 25 finestre invece di 24, nop_s a 0xD052E). Contributi ulteriori dell'audit:

- **Validazione dell'encoding BL ARC700** su 114.683 campioni (4 famiglie di costante, campo basso = (4k & 0x7FF)): i commenti `;0xtarget` GNU dei bl sono corretti; nessuna mnemonica diversa da `bl` riferisce 0xCA404 o 0xCBC00 su tutto il listing.
- **LE 0x000CA404**: un'unica occorrenza in tutti i payload, p9 @0xEF3AE2 (≡2 mod 4), dentro una tabella dati a stride 4: né pool né puntatore né limm (manca l'istruzione consumatore) → nessun riferimento statico a 0xCA404 oltre i 63 bl.
- **Sei falsi branch** che puntano dentro siti di chiamata (0x3BF35C, 0x8452F8 → 0x80D45C; 0x8504E6 → 0x651DDE; 0x854734 → 0x656032; 0x8408B0 → 0x8022B8; 0x10A2808 → 0x1747B6): tutti in tabelle dati (fill 0xff, stride costante), irraggiungibili come codice; non-reachabilità argomentata per pattern, non prova formale.
- **Nessun secondo getter di 0x3657C8** (unico riferimento statico al pool 0xD0530 = la `ld_s` del getter; nessun limm) e **nessuno scrittore statico** anche entro ±512 byte da tutti i 31 riferimenti ai 14 pool della struct.
- Il banco CPU dell'agente loopava per un errore del suo stesso banco (bl assemblato male) e, come concordato, i casi CPU sono stati verificati sulle evidenze congelate: PT_LOAD@0xCBC00 == byte originali in tutti gli ELF esaminati, fault e conteggi istruzioni come da claim.

Dopo l'audit il verificatore è stato corretto nella sola docstring/prosa e nel pattern del gate 0x7CB62E (esteso a 0x7CB610–0x7CB61A, byte-verbatim), e rieseguito: **PASS_CAPTURE_TRANSITION_CALLER_CENSUS 20261101T115840936113Z**. Le asserzioni congelate non sono state indebolite.

## Prossimo passo

(a) **Produttore runtime della 0x3657C8**: nessuno scrittore statico diretto — cercare copie bulk della struct 0x365750 o i 6 chiamanti non-feeder di 0xD0528 (0x252C0E, 0x25327A, 0x7F6AF4, 0x7F8ACC, 0x7FAA50, 0x7FBE3A) per capire chi stabilisce la «modalità desiderata» e quando diverge da 0xC8E80C; è il pezzo che rende i 15 feeder prevedibili. (b) In alternativa, decodificare i gate contesto dei due chiamanti della switch (0xce238, 0x15b024, struct 0x681FF0/0x682098 di payload2) per collegarli agli handler AutoScene/CaptureMenu già studiati. Il punto census transizione/switch è CHIUSO: non rieseguire i census né l'audit di questi claim.
