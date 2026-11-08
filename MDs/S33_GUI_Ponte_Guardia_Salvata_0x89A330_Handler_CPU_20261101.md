# Ponte 0x89A330 → guardia CaptureMenu: i quattro handler fratelli della finestra 0x99AB8C che consumano la cella del gate — 1 novembre 2026 (iterazione 44)

## Domanda

Punto aperto (a) dell'iterazione 43 ([rapporto](S33_GUI_Cella_Desiderata_Restore_Census_CPU_20261101.md)): decodificare i contesti di **0x7F8694/0x7F8764** (i lettori del byte `[0x89A330]` passati al setter guardia 0xCA2F4) e di **0x7F947E** (il dispatch 0..4 sulla stessa cella) — gate, condizioni e ordine rispetto all'handler 0x4405/attesa 0x158d04 — per stabilire se **la guardia salvata** che il gate dell'evento 0x4405 copia in 0x89A330 **rientra nella guardia CaptureMenu 0x365751**. È il pezzo che chiude il collegamento restore→guardia/flag delle iterazioni 39–41.

## Verificatore ed esiti

- Script: `Python_Trace_Scripts/s33_verify_capture_saved_guard_bridge_cpu.py` (statico byte-esatto + 10 casi CPU con byte firmware originali).
- `python3 Python_Trace_Scripts/s33_verify_capture_saved_guard_bridge_cpu.py` → **PASS_CAPTURE_SAVED_GUARD_BRIDGE 20261101T131950005757Z**; riesecuzione identica → **PASS_CAPTURE_SAVED_GUARD_BRIDGE 20261101T132020022000Z** (tutti i 10 casi CPU: fault `0xdeadaa01`, exit 11); post-audit (docstring corretto su 35 coppie/terminatore 0x99ACA4/array da 0x99ACAC, asserzioni e dati congelati invariati) → **PASS_CAPTURE_SAVED_GUARD_BRIDGE 20261101T132744210279Z**.
- [Evidenze](../Risultati/GUI_S33/saved_guard_bridge_cpu_20261101T131950005757Z/) (`verified_evidence.json` + `static_evidence.json`, ELF/assembler/linker script/log per caso, estratto della divergenza b-decode con i micro-test `bneg.s`/`bneg2.s`); [riesecuzione](../Risultati/GUI_S33/saved_guard_bridge_cpu_20261101T132020022000Z/).
- Regressioni rieseguite tutte PASS: guard setter census **20261101T132027089262Z**, flag mode matrix 14 casi **20261101T132042652111Z**, snapshot record init 4 casi **20261101T132055686184Z**, service raise pending **20261101T132043Z**.

## Risultato 1 — la tabella eventi 0x99AB8C è COMPLETA e contiene i quattro handler del ponte

Enumerazione congelata (payload5, base 0x897800): **35 coppie (evento, handler)** da 0x99AB8C a 0x99AC9C, terminatore `(0x0000, 0x20E814)` a **0x99ACA4**. Le voci nuove oltre la lista it.43:

| evento | handler | ruolo |
|---|---|---|
| **0x3B81** | **0x7F8674** | ponte A: modo desiderato + guardia := [0x89A330] |
| **0x3301** | **0x7F86C0** | ponte C: guardia := 0 + stb 2/1 su struct 0x89A2FC + modo desiderato |
| **0x3181** | **0x7F871C** | ponte B: come A con gate 0x137774 opzionale + 0xCB5E4 |
| **0x4006** | **0x7F877C** | guardia := 0 + dispatcher 0x7F9468 + 0x14905C(ctx,0x19,500,0) |
| 0x3081 | 0x7F85B4 | non decodificato |
| 0x4001 | 0x7F860C | non decodificato |
| 0x4110 | 0x7F9E6C | non decodificato |
| 0x3281 | 0x7F863C | non decodificato |
| 0x4002 | 0x7F9EB4 | non decodificato |

Dopo il terminatore, a 0x99ACAC..0x99ACC8, **16 ID evento packed come halfword** in 8 word (la word a 0x99ACAC è 0x04810480): `0x0480,0x0481, 0x0500,0x0501, 0x0380,0x0381, 0x0400,0x0401, 0x0580,0x0700, 0x2180,0x2700, 0x0581,0x0701, 0x2181,0x2701` — l'array contiene **i quattro slot logici pulsante già studiati** (0x580/0x581, 0x700/0x701, 0x2180/0x2181, 0x2700/0x2701) accanto ad altre coppie. Semantica dell'array (sottoscrizione/inoltro eventi) NON dimostrata.

Censimenti congelati: i quattro handler del ponte hanno **ZERO chiamanti bl** in tutto il firmware e **esattamente una parola LE ciascuno**, alla propria cella in tabella (0x99AC98/0x99AC80/0x99AC88/0x99AC90): sono **callback puri della stessa finestra** che possiede l'handler 0x4405→0x7F6A90 (0x99AB98) e l'evento pulsante 0x2180→0x7F7F8C (0x99ABD4/D8).

## Risultato 2 — ponte A (0x3B81 → 0x7F8674) e ponte B (0x3181 → 0x7F871C): la guardia salvata RIENTRA nella guardia CaptureMenu

Finestra congelata 0x7F8674..0x7F86B8 (byte originali eseguiti in CPU):

1. `bl 0xD0528` (getter della **modalità desiderata** 0x3657C8, it.41–42) → r0;
2. `bl 0xCA404` (transizione di modalità, it.40–41) con r0 = modalità desiderata;
3. `ld_s r0,[pcl,0x2c]` → pool 0x7F86BC = **0x89A330**; `ldb_s r0,[r0,0]`;
4. `bl 0xCA2F4` → **guardia 0x365751 := byte [0x89A330]** (setter originale);
5. `bl 0x1453E4(0x5E, 0)` (notifica);
6. `bl 0x210BE4` condizionale: se ≠0 seconda chiamata e `bl 0x20E814(r13, r14, r2)` (forward), altrimenti uscita; epilogo condiviso 0x7F6A80.

Il ponte B (0x7F871C) è identico nei passi 1–4 con in più un blocco opzionale davanti (gate `0x137774(0)`, `0x135a84/0x135a90`, gate 0x7F936C, `0xD1644(1)`), `bl 0xCB5E4` dopo il setter e forward `(r14,r15,r16)` con epilogo 0x7F7408.

**Chiusura del ciclo (dataflow, vedi Limiti):** il gate dell'evento 0x4405 (it.43) scrive in 0x89A330 **0** (se `0x14504C(arg,0x12)==3`) oppure **la guardia salvata 0x3657CC** (snapshot preso da 0xD0478 all'uscita dal modo di scatto, it.42). Gli handler fratelli 0x3B81/0x3181 leggono quella cella e la copiano nella guardia CaptureMenu. Quindi, quando la query del gate non è 3, **la guardia salvata rientra nella guardia viva** — la condizione che nel modo 0x2C mantiene selezionabili le voci 0x0A/0xBB della lista 0x4801 (it.39–40). L'ordine interno è: PRIMA la transizione alla modalità desiderata (dove 0xCA404 può già ripristinare guard=7 dal flag 0x36580C, it.40), POI la sovrascrittura esplicita con [0x89A330].

Casi CPU (byte originali, getter/setter/transizione/stub notify originali o recorder):
- `bridge_a7`: [0x89A330]=7 → guardia 0x365751 == 7, transizione riceve 0x2C (da [0x3657C8]=0x2C), notify (0x5E,0), **forward preso** (0x210BE4 contato 2 volte, 0x20E814 con (0x6001,0x6002,1)), cella salvata 0x3657CC intatta, sentinelle intatte.
- `bridge_a0`: [0x89A330]=0 → guardia == 0, **forward NON preso** (0x210BE4 contato 1 volta, log del forward a zero), transizione comunque 0x2C.
- `bridge_b3`: [0x89A330]=3 → guardia == 3, 0x137774(0)→1 salta il blocco opzionale, 0xCB5E4 riceve r0=3 (**il setter 0xCA2F4 preserva r0**: `stb_s r0,[r1,0]` con epilogo che non tocca r0), forward (0x6001,0x6002,0x6003).

## Risultato 3 — ponte C (0x3301 → 0x7F86C0): guardia := 0 e scrittura su struct 0x89A2FC

Finestra congelata 0x7F86C0..0x7F8718: gate **0x7F936C** (v. Risultato 5); se ≠0 → `bl 0x7F9BD4(ctx,1)`; poi `bl 0xCA2F4` con **r0=0** (guardia azzerata); poi `ld.as` (EA scalata (PC&~3)+imm*4, it.40) carica **[0x89A31E]** (pool 0x7F8370) e la base **0x89A2FC** (pool 0x7F830C): se il byte è ≠0 → `stb 2 → [0x89A2FC+0x24]` e USCITA (senza transizione); se ==0 → `stb 1 → [0x89A2FC+0x2A]`, poi transizione alla modalità desiderata + forward `(r14,r13,r15)`. Casi CPU `bridge_c_set2`/`bridge_c_set1`: entrambe le vie di store provate con byte originali, guardia == 0 in entrambe, gate originale che legge [0x89A330]=5 senza interrogare 0x14918C, celle sorelle e 0x89A330 invariate, `0x7F9BD4`/`0x14918C` volutamente NON stubbate (raggiungerle avrebbe fatto fallire il caso).

## Risultato 4 — il dispatcher 0x7F9468 (0x7F947E): la cella 0x89A330 pilotata su tre risorse della finestra

Tre chiamanti bl (0x7F83FE, 0x7F87C2 dentro l'handler 0x4006, 0x7F88D6). Finestra congelata 0x7F9468..0x7F94DE:

1. `bl_s 0x7F936C` (gate); se ≠0 → uscita senza aggiornamenti;
2. `ld_s r0,[pcl,0x68]` → pool 0x7F94E4 = **0x89A330**; `ldb_s`;
3. `cmp_s r0,0x4; bhi_s` → via 0; altrimenti **jump table a 0x7F9492** (byte `0a 03 03 03 03`, add1_s = offset halfword): valore **0 → 0x7F94A6** (r13=r15=r16=0), valori **1..4 → 0x7F9498** (`mov r13,805=0x325; mov r15,296=0x128; mov r16,292=0x124`);
4. tre chiamate `bl.d 0x145654(ctx, resid)` con delay slot che carica r1 = **0x4831** (pool 0x7F94E8), **0x482E** (0x7F94EC), **0x482F** (0x7F94F0), e `bl 0x633768(handle, sexw(r13/r15/r16), 0)`.

Casi CPU: `disp_v0` → tripla (0,0,0); `disp_v1`/`disp_v4` → (0x325,0x128,0x124) sulle tre risorse in ordine 0x4831/0x482E/0x482F; `disp_v5` → (0,0,0) (via `bhi`, ramo diverso da v0); `disp_v1_q1skip`: con la query del gate che risponde 1 il gate ritorna 1 e il dispatcher **esce senza alcuna chiamata** alle risorse. I valori 0x325/0x128/0x124 appaiono come ID/valori da assegnare; il significato delle tre risorse NON è decodificato.

## Risultato 5 — il gate 0x7F936C: la struct 0x89A2FC ha base diversa ma la stessa cella 0x89A330

Finestra congelata 0x7F936C..0x7F93A6: `ld.as r13,[pcl,-174]` → **pool reale 0x7F90B8 = 0x89A2FC** (commento objdump `;0x7f92c2` non scalato, ingannevole — regola it.40 confermata su questo nuovo sito in CPU); `ldb r0,[r13,52]` → **0x89A2FC+0x34 = 0x89A330**: il gate legge la STESSA cella del ponte con una base struct diversa (0x89A2FC vs 0x89A318+0x18, it.43). Se il byte è 1 o 2: `ld_s r0,[r13,0xC]` (word handle), `mov r1,3`, `bl 0x14918C(handle,3)`; se ritorna 1 → gate = 1, altrimenti 0. Epilogo condiviso 0x3341A4 (famiglia: `mov r12,4; mov r13,4; b 0x3341DA; ld.ab r13,[sp,r13]; ld.ab blink,[sp,r12]; j_s [blink]`) eseguito con **byte originali** in tutti i casi gate. 12 chiamanti bl censiti (0x7F6944, 0x7F7E56, 0x7F7EE8, 0x7F7FC0, 0x7F84E0, 0x7F8556, 0x7F86D4, 0x7F8748, 0x7F8EC2, 0x7F92F0, 0x7F9478, 0x7F9BE6).

**0x7F9BD4(ctx, r13)** (5 chiamanti; statico, non eseguito in CPU): gate 0x7F936C; se 0 esce; r15=0; **se r13==0 → guardia := 0 via 0xCA2F4(r15=0)**; word **[0x89A310] := 0** (pool 0x7F9CA4); poi 0x149028(ctx,3/6/4), 0x143afc(9/0xB/0xA), 0x176828(2,0,0x32).

## Risultato 6 — handler 0x4006 (0x7F877C, statico): l'altro azzeratore di guardia

0x20E814, 0xC7E04; se il risultato è 1 controlla il selettore a 3 vie **[0x89A2FC+0x10/0x11/0x12]** (pool 0x7F8814) e il byte **[0x681EEB]** (pool reale 0x7F85B0: `ld.as` con EA=(PC&~3)+imm*4, commento `;0x7f8730` non scalato); in caso contrario **guardia := 0**, `bl 0x7F9468(ctx)`, `0x14905C(ctx, 0x19, 500, 0)`, `0xCD8CC`. Il corpo oltre la finestra congelata non è decodificato.

## Risultato 7 — divergenza strumento (LEZIONE DI BANCO, documentata)

La `b` 32-bit che chiude le finestre del ponte (0x7F86B6, W = 0xFF0F03CD, displacement negativo, PC≡2 mod 4) è decodificata da **GNU objdump** come target `(PC&~3)−7220 = 0x7F6A80` (l'epilogo condiviso) e dal **simulatore GNU ARC700** come `(PC&~3)+972 = 0x7F8A80`: delta esatto **0x2000 = 8192**, cioè il sim applica al campo displacement un **wrap mod 8192** invece dell'estensione di segno (−7220+8192 = +972). Il `bl` 32-bit retrocesso alla stessa alignment (0x7F86B2 → 0x20E814) è invece eseguito in perfetto accordo GNU/sim, e i micro-test `bneg.s`/`bneg2.s` (b/bne 32-bit GNU assemblati con displacement −16/−18, anche a PC≡2 mod 4) sono eseguiti correttamente dal sim: la divergenza osservata riguarda i **bit alti del campo** (displacement grandi/negativi). Conseguenze adottate: **nessun caso CPU esegue una `b` 32-bit del firmware** — le finestre sono tagliate prima della `b` e sostituite da un trampolino hand-encoded (`W = d+1`, d piccolo positivo, forma identica ai `b` con label GNU) verso il probe. Quale decodifica corrisponda all'hardware ARC700 reale NON è stabilito. Evidenza: estratto del trace e micro-test in [prove](../Risultati/GUI_S33/saved_guard_bridge_cpu_20261101T131950005757Z/b_decode_divergence_trace_excerpt.txt).

## Risultato 8 — audit indipendente (agente bridge-audit-45) e famiglia estesa dei ponti

**Agente `bridge-audit-45`** (tools.agents.spawn, atteso e integrato; «task con agente explore» inesistente in questo ambiente, come documentato): metodo indipendente (16 blocchi TBM verificati sha256, finestre ridisassemble ex-novo, census proprio con target ricalcolati, LE scan a ogni offset, tracer statico registro→pool, evidenze congelate lette senza rieseguire nulla) → **C2–C9 CONFERMATI byte-esatti**; **C1 confutato SOLO nel docstring** (35 coppie, terminatore a 0x99ACA4, array da 0x99ACAC: il codice e le evidenze erano già corretti; docstring corretto e verificatore rieseguito PASS 20261101T132744210279Z con asserzioni invariate).

**Tre ulteriori handler ponte cella→guardia nella STESSA finestra** (controesempi al census del banco; trovati dall'audit e riverificati byte-esatto in coordinatore — la conclusione ne esce rafforzata):

| evento | handler | lettura [0x89A330] | setter |
|---|---|---|---|
| 0x0100 | 0x7F7EB0 | pool 0x7F7B84=0x89A2FC, `ldb [r14,52]` a 0x7F7F00 | `bl 0xCA2F4` a 0x7F7F04 |
| 0x0180 | 0x7F7FAC | pool 0x7F7FFC=0x89A2FC, `ldb [r0,52]` a 0x7F7FDA | `bl 0xCA2F4` a 0x7F7FDE |
| 0x0400/0x0480/0x0500 | 0x7F850C | pool 0x7F830C=0x89A2FC, `ldb [r14,52]` a 0x7F8574 | `bl 0xCA2F4` a 0x7F8578 |

Tutti seguono lo stesso schema (gate 0x7F936C → 0x7F9BD4(ctx,1) → getter 0xD0528/transizione 0xCA404 → `[base+52]` → setter → 0xCB5E4/notify). Con i quattro del banco, **almeno sette handler della finestra** copiano [0x89A330] nella guardia; altri tre chiamanti di 0xCA2F4 in p4 (0x7D7D08, 0x7F76B2 con costante 0, 0x7F83C4) sono fuori dalla famiglia.

**Altri lettori di 0x89A330 censiti dall'audit** (non nel banco): **0x7F6C84** (`ldb [r15,52]` dentro l'handler 0x4405/0x7F6A90 stesso), **0x7F9B34** (famiglia 0x7F9B1E che richiama 0x7F9B00), **0x7F9DF2** (`ld.as` → pool 0x7F9B14; se 0 → `bl_s 0x7F9CD8`). Scrittori: confermati solo i due store del gate (0x7F6AE2/0x7F6AEC). **0x20E814**: 215 chiamanti bl in p4 — helper molto condiviso; «forward» resta interpretazione contestuale (il banco prova solo gli argomenti ricevuti dallo stub).

## Fonti precise

- Payload4 (base 0x796800): handler 0x7F8674..0x7F86B8 (+pool 0x7F86BC), 0x7F871C..0x7F8776, 0x7F86C0..0x7F8718, 0x7F877C..0x7F87DC; dispatcher 0x7F9468..0x7F94DE (+pools 0x7F94E4/E8/EC/F0, jump table 0x7F9492); gate 0x7F936C..0x7F93A6 (+pool 0x7F90B8); 0x7F9BD4..0x7F9C30 (+pool 0x7F9CA4); pool 0x7F8370=0x89A31E, 0x7F830C=0x89A2FC, 0x7F8814=0x89A2FC, 0x7F85B0=0x681EEB; epilogo condiviso 0x7F6A80/0x7F7408; ponti estesi 0x7F7EB0 (+pool 0x7F7B84), 0x7F7FAC (+pool 0x7F7FFC), 0x7F850C (+pool 0x7F830C); lettori aggiuntivi 0x7F6C84, 0x7F9B34, 0x7F9DF2.
- Payload5 (base 0x897800): tabella eventi 0x99AB8C..0x99ACA4, array ID evento 0x99ACAC..0x99ACCC.
- Payload0 (base 0xAD800): getter cluster 0xD04C8..0xD0534 (0xD0528 → 0x3657C8 via pool 0xD0530), setter/getter guardia 0xCA2F4..0xCA310 (pool 0xCA30C=0x365751), prologhi 0x33412C/0x334128, epilogo condiviso 0x3341A4..0x3341E4.
- Evidenze: [prove PASS](../Risultati/GUI_S33/saved_guard_bridge_cpu_20261101T131950005757Z/), [riesecuzione](../Risultati/GUI_S33/saved_guard_bridge_cpu_20261101T132020022000Z/), run interrotto con la b eseguita (finestra non tagliata) `saved_guard_bridge_cpu_20261101T131255364220Z/` (trace da 500 MB rimosso, estratto conservato).

## Limiti

- Statico + 10 casi CPU sintetici (fixture su 0x3657C8/0x365751/0x89A2FC/0x89A330; prologhi, epilogo 0x3341A4, getter e setter ORIGINALI; transizione, notify, forward, gate-query, risorse come stub recorder): nessun hardware, scatto, rendering, persistenza.
- **Chi invia gli eventi 0x3B81/0x3181/0x3301/0x4006 NON è tracciato**: l'ordine rispetto all'handler 0x4405/attesa 0x158d04 è **dataflow** (chi produce 0x89A330 e chi lo consuma), NON schedulazione runtime dimostrata. Il collegamento save→0x4405→0x89A330→0x3B81/0x3181→guardia è coerente con it.42–43 ma resta una catena di dati, non una sequenza temporale provata.
- Il target della `b` finale degli handler (epilogo condiviso 0x7F6A80/0x7F7408) NON è provato in CPU (v. Risultato 7); il suo significato di «epilogo» è dall'analisi statica GNU.
- Corpi oltre le finestre congelate (0x210BE4, 0x14918C, 0x145654, 0x633768, 0x149028, 0x143afc, 0x176828, 0xC7E04, 0x14905C, 0xCD8CC, handler 0x3081/0x4001/0x4110/0x3281/0x4002) NON decodificati; significato delle risorse 0x4831/0x482E/0x482F e dei valori 0x325/0x128/0x124 APERTO; semantica dell'array di 16 ID evento APERTA.
- V1.1 campione vs macchina V1.0. Circa 10% invariato; NON_INSTALLARE.
