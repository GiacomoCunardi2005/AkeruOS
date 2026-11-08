# Event router WindowManager e produttori degli eventi ponte: la coda GUI 0x17BC7C/0x17BD4C, il resolver 0x169E1C→[0x366EA4], il router 0x7F6824→0x169F60 con lista di esclusione 0x99ACAC e 8 casi CPU su byte originali — 1 novembre 2026 (iterazione 45)

## Domanda

Punto aperto (a) dell'iterazione 44: **chi invia gli eventi del ponte 0x3B81/0x3181 (e i ponti estesi) alla finestra con tabella 0x99AB8C**, partendo dall'array di 16 ID a 0x99ACAC e dal ciclo WindowManager — per trasformare il dataflow «save → 0x4405 → 0x89A330 → ponte → guardia» in una sequenza runtime dimostrata.

## Verificatore

`Python_Trace_Scripts/s33_verify_event_router_producers_cpu.py` → **PASS_EVENT_ROUTER_PRODUCERS 20261101T134913644349Z**; riesecuzione identica **20261101T134925410763Z** (differisce solo `utc`). Prove: `Risultati/GUI_S33/event_router_producers_cpu_20261101T134913644349Z/` (+ `event_router_producers_latest.json`). Regressioni tutte PASS: guard setter census **134925410092Z**, flag matrix 14 casi **134938244668Z**, snapshot record init 4 casi **134942354038Z**, service raise pending **134943Z**.

## Risultato 1 — catena di consegna eventi GUI (statica, bl/pool byte-verificati)

```
produttore → 0x169EB4(desc,evento,arg) / 0x169F40 / 0x169F00   [wrapper di post]
           → 0x17BC7C  insert coda ad anello                    [o 0x17BCE4 push-front]
           → ciclo 0x15AF1C..0x15AF48 → 0x17BD4C extract
           → 0x169E1C(desc, evento, arg)
                evento==0x440F → 0x1453E4(lo16(arg), hi16(arg))   [richiesta per id]
                desc==0 ∧ evento<0x4400 → 0x1453F4 = [[0x366EA4]] [finestra corrente]
           → 0x169D78(nodo, evento, arg)
                ~~nodo≤8 → jump table 0x169DDC (funzioni per-id 0x16A0BC…)~~ [ERRATA 1 nov 2026: lo switch è sull'EVENTO, v. S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md]
                ~~nodo>8 → pool 0x16A160 = 0x16A6E4 (LE unica in p0)~~ [ERRATA: default per evento fuori 0x4401..0x4409 e non 0x5401-3]
           → 0x16A6E4 → 0x16A028 (19 siti bl, invoker condiviso)
           → 0x14505C(nodo) = callback → [nodo+0xC]
           → router 0x7F6824 (nodo 0x99AB6C)
                evento ∈ [128,0x307F] → macchina tasti (stato 0x16F920, classi evento>>7)
                altrimenti → 0x169F60(0x99ACAC, 0x99AB8C, arg0, evento, arg2)
           → 0x169F60: scan array 0x99ACAC (halfword, terminatore 0):
                evento NELL'array → ritorna 0 SENZA dispatch   [lista di ESCLUSIONE]
                altrimenti scan tabella (id,handler) a 8 byte, terminatore id 0
                → handler(ctx)
```

- **Nodo finestra 0x99AB6C** (payload5): id 0x402, flag 0x0021007E, lista sottofinestre 0x99AAE8, **callback +0xC = 0x7F6824** (LE di 0x7F6824 **unica** nei 16 payload, a 0x99AB78), tabella eventi +0x20 = 0x99AB8C. Il vecchio descrittore 0x99AB40 (+0x2C=0x402) è la stessa struttura letta da offset diverso.
- **0x169E1C**: UNICO chiamante bl = 0x15AF42 nel ciclo 0x15AF1C..0x15AF48 (estrazione 0x17BD4C, consegna `ldh.x r1,[sp,4]`).
- **Pool router**: 0x7F6A48=0x99ACAC e 0x7F6A4C=0x99AB8C sono le UNICHE LE di quei valori in tutti i payload.
- **Coda ad anello**: base record **0x47A848** (pool 0x17C000), record {u16 arg0 a +0, u16 evento a +4, u32 arg a +8}, **stride 12**, **128 voci** (bmsk 0x7F), indici halfword a **0x367BBC** (pool 0x17BFF8): read a +0, **write a +2** (offset `[r2,2]` di ldw_s.x/stw_s NON scalato — provato in CPU). Insert 0x17BC7C (3 chiamanti bl: 0x1492F6, 0x169EF4, 0x16F71E), push-front 0x17BCE4 (1: 0x169F36), extract 0x17BD4C.
- Nuova coppia lifecycle identificata: 0x169FBC (setter "ultimo evento" [0x367814]) consegna **0x4411/0x4412** via 0x169D78 (pool 0x16A16C/0x16A170).

## Risultato 2 — census dei produttori degli eventi ponte

Classificazione di TUTTI i chiamanti bl di 0x169EB4 (304), 0x169F40 (28), 0x169F00 (33) per argomento evento r1 (pool pcl o costante); pool word di ogni sito verificate byte-esatte (= id evento).

| Evento | Siti produttore (tutti desc=0, cioè finestra corrente) |
|---|---|
| **0x3181** (ponte B) | **11**: 0xC9A7C, 0x2CCBCE (p0); 0x65CAB0 (p2); 0x7E33BE, 0x7E3BD0, 0x7FDE46, 0x7FE36E, 0x80095E, 0x802626 (p4); 0x9D82DA, 0x9DBEEA (p6) |
| **0x3301** (ponte C) | **4**: 0x2D348C, 0x2D40C4 (p0); 0x9D1F70 (p6); 0x803422 (p4) |
| **0x3B81** (ponte A) | **1**: 0x8101DC via 0x169F40; **wrapper 0x8101C8** (pool 0x8101EC=0x3B81) con UNICO chiamante bl **0x80B48E**, caso 229 di un dispatcher su id messaggio (226/227/228/229), arg dal record; 0x8101C8 ha ZERO parole LE |
| 0x3081 | 1: 0x7E8D66 |
| 0x3101 | 1: 0x7F73E2 |
| 0x3281 | 7: 0x7FA986, 0x7F888E, 0x7FF6EA (p4); 0x13556E (p0); 0x9D47E2, 0x9D621E, 0x9E1DC4 (p6) |
| **0x4006** (ponte D) | **NESSUN produttore a costante** nelle API di post; la word LE 0x4006 compare come voce in ≥8 tabelle evento di payload5 (0x98E7E0, 0x99AC8C, 0x99BBDC, 0x99C5D8, 0x99C8AC, 0x99D4DC, 0x9A0688, 0x9A3034) e in dati p0/p1/p3/p6 → **consegna broadcast non identificata: APERTO** |

Eventi tasto con produttore diretto via 0x169EB4: 0x0380×8, 0x0400×10, 0x0480×4, 0x0500×4, 0x0580/0x0581×2, 0x0700/0x0701×2, 0x2181×1, 0x0600×3 (per gli slot logici pulsante il percorso snapshot→coda resta quello già studiato).

**Semantica di 0x169F60 (nuova, CPU-provata): l'array di 16 ID a 0x99ACAC è una LISTA DI ESCLUSIONE** — l'evento presente nell'array NON viene dispatchato dalla tabella (ritorno 0). Gli ID pulsante 0x580/0x700/0x2180/0x2700 e le coppie 0x0380/0x0400/0x0480/0x0500 sono gestiti dalla macchina tasti del router, non dalla tabella, attraverso questa esclusioni.

## Risultato 3 — 8 casi CPU su byte originali (GNU ARC700)

Finestre ORIGINALI: router 0x7F6824..0x7F6A28 (516 byte, tagliata prima della b finale), 0x169F60..0x169FB0, handler 0x7F871C..0x7F8776, post 0x169EB4/0x17BC7C, extract 0x17BD4C, deliver 0x169E1C, resolver 0x1453F4, getter 0xD0528, setter 0xCA2F4, prologhi 0x334120..0x33413A, nodo e tabella copiati dai byte originali di payload5. Stub agli indirizzi originali; trampolini hand-encoded ai tagli (metodo it.44).

| Caso | Catena eseguita | Esito |
|---|---|---|
| post3181 | 0x169EB4(0,0x3181,0x77) → 0x17BC7C → record {0,0x3181,0x77} a 0x47A848, write=1, read=0 | fault **0xDEADA201** |
| post3181_overflow | anello pieno (write=0x7F): NESSUN insert, NESSUN segnale, record/indici intatti | fault **0xDEADA202** |
| extract3181 | 0x17BD4C(buf) sull'anello del caso 1 → buf={0,0x3181,0x77}, read avanza a 1 | fault **0xDEADA301** |
| extract3181_empty | anello vuoto → errore 0x1594A4 chiamato una volta, buf intatto | fault **0xDEADA401** |
| resolve3181 | 0x169E1C(0,0x3181,0x77) con [0x366EA4]=0x99AB6C → 0x1453F4 risolve il nodo → 0x169D78 riceve (0x99AB6C,0x3181,0x77) | fault **0xDEADA501** |
| resolve3181_none | [0x366EA4]=0 → 0x169D78 NON chiamato | fault **0xDEADA601** |
| **dispatch3181** | router 0x7F6824(0x6001,0x3181,0x77) → 0x169F60 (array esclusione, tabella) → **handler 0x7F871C** → transizione modo 0x2C → **guardia 0x365751 := [0x89A330] = 7** → 0xCB5E4(r0=7) → forward (0x6001,0x3181,0x77); sequenza ordine di 7 stub verificata | fault **0xDEADA701** |
| dispatch3181_blocked | array RAM patchato con 0x3181 → 0x169F60 ritorna 0, handler MAI chiamato, guardia sentinella intatta, store del router [0x89A322]=0 ne prova l'esecuzione | fault **0xDEADA801** |

Il caso dispatch3181 esegue in sequenza su byte originali: prologo 0x334124, router 0x7F6824, 0x169F60, prologo 0x334128, handler 0x7F871C, getter 0xD0528, setter 0xCA2F4 — il ponte B completo: **l'evento 0x3181 postato dal produttore arriva alla guardia CaptureMenu passando dal router e dalla tabella della finestra** (concatenazione per stadi; v. Limiti per il ciclo e il nodo corrente, statici in questo banco).

## Lezioni di banco (nuove, documentate)

1. **Delay slot in 0x17BC7C**: il delay slot `mov r17,r0` di `bl.d 0x1786e8` copia r0 PRIMA della chiamata → r17 contiene il **token di sezione critica restituito da 0x1593AC** (delay slot del bl.d precedente), NON il ritorno di 0x1786E8; con lock stub a 0 l'inserimento cade nel percorso d'errore 0x1594A4.
2. **Offset [r2,2] di ldw_s.x/stw_s NON scalato**: l'indice write della coda sta a 0x367BBE (+2), non a +4 (provato in CPU: il probe che controllava +2 passa, +4 falliva).
3. **Trampolini**: quando il landing confina con pool originali (0x7F6A28 vs pool 0x7F6A2C) il trampolino è di 4 byte senza nop; i probe check-and-fault non richiedono MAI l'emulazione dell'epilogo (scelta progettuale che ha evitato l'ambiguità ld.ab).
4. Lo stub con log d'ordine richiede r6 = base+44+8k (`add r6,r6,r3`): senza la base gli store finivano a 0x2C.

## Comandi/esiti

`python3 Python_Trace_Scripts/s33_verify_event_router_producers_cpu.py` → **PASS_EVENT_ROUTER_PRODUCERS 20261101T134913644349Z**; riesecuzione **134925410763Z** identica (verifica campo-per-campo: producers, censuses, LE scan, pool, cpu_cases tutti `identical: True`, solo `utc` differisce). Correzioni di banco durante lo sviluppo (documentate, asserzioni invariate): census 0x17BC7C in ordine di file; sezioni orig nel ld script generate dalle finestre; sezione .stack 16384 byte nell'asm; finestre pool mancanti (0x17BFF4-0x17C004, 0x16A12x, 0x14579C) aggiunte ai casi; token lock ≠0; `asl_s` r4 rifiutato dal vecchio as (3×add); stub 0x135A84 corto (12 byte di spazio); stub_order EA con base; probe del caso blocked al taglio 0x169FB0.

## Agente e MCP

**Agente `router-audit-14`** (tools.agents.spawn; l'audit era stato avviato come `router-producers-audit-45` nella sessione interrotta per timeout e rilanciato in questa): revisione indipendente dei claim C1-C8 con metodo proprio (decoder BL/bl_s ex-novo, census e LE scan propri, parser ELF32 sugli ELF congelati). Esiti: C1/C2/C3/C6/C7 CONFERMATI; C4/C5 PARZIALI — CONFUTATO il claim forte «0x4006 nessun produttore» (produttori `bset bit14`: 0x4006 ×5, 0x4001 ×4, 0x4002 ×29, più 0x4003/0x4005; riverificati byte-esatto 0xCB950 e 0x20F972 in questa sessione) e confermata la correzione dello switch su EVENTO di 0x169D78 (errata sopra). Dettagli, controesempi C8 e correzioni: [S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md](S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md), sezione «Audit indipendente». Server MCP: `mcp_pmb_nikon` (prepare iniziale + record_batch finale; l'audit ha registrato il proprio esito in PMB, outbox 378). REA non presente tra i connettori. «task con agente explore» inesistente in questo ambiente (documentato nelle iterazioni precedenti).

## Fonti precise

- Payload0 (base 0x0AD800): wrapper 0x169EB4..0x169EFA (pool 0x16A130=0x36780C); insert 0x17BC7C..0x17BCDE (pool 0x17BFF4=0x300008, 0x17BFF8=0x367BBC, 0x17BFFC=0x300004, 0x17C000=0x47A848); extract 0x17BD4C..0x17BD90; deliver 0x169E1C..0x169E96 (pool 0x16A128=0x367800); resolver 0x1453F4..0x1453FA (pool 0x14579C=0x366EA4); dispatcher 0x169F60..0x169FB0; invoker 0x16A028 (19 bl), 0x16A6E4 (pool 0x16A160, unica LE); prologhi 0x33411C..0x33413A, epiloghi 0x33413C..0x3341E4; wrapper 0x8101C8 (pool 0x8101EC), chiamante 0x80B48E; ciclo 0x15AF1C..0x15AF48.
- Payload4 (base 0x796800): router 0x7F6824..0x7F6A28 (pool 0x7F6A2C=0x89A318, 0x7F6A30=0x89A2FC, 0x7F6A48=0x99ACAC, 0x7F6A4C=0x99AB8C); handler 0x7F871C..0x7F8776 (pool 0x7F86BC=0x89A330); produttori 0x7E33BE, 0x7E3BD0, 0x7E8D66, 0x7F73E2, 0x7F888E, 0x7FA986, 0x7FDE46, 0x7FE36E, 0x7FF6EA, 0x80095E, 0x802626, 0x803422, 0x8101DC.
- Payload5 (base 0x897800): nodo 0x99AB6C..0x99AB8C (callback 0x99AB78=0x7F6824), tabella 0x99AB8C..0x99ACAC (35 coppie + terminatore), array 0x99ACAC..0x99ACCC; parole 0x4006 in 0x98E7E0, 0x99BBDC, 0x99C5D8, 0x99C8AC, 0x99D4DC, 0x9A0688, 0x9A3034.
- Payload1: celle hook 0x367800/0x367808/0x36780C/0x367810 (letture, non pool); coda 0x367BBC/0x47A848.
- Evidenze: `Risultati/GUI_S33/event_router_producers_cpu_20261101T134913644349Z/` (8× .s/.ld/.elf/.bin, verified_evidence.json), riesecuzione `..._20261101T134925410763Z/`, `event_router_producers_latest.json`.

## Limiti

- Statico + 8 casi CPU sintetici: nessun hardware, scatto, rendering, persistenza; NON_INSTALLARE; circa 10% invariato.
- Il ciclo WindowManager 0x15AF1C e le funzioni 0x16A6E4/0x16A028/0x14505C sono **solo statiche** in questo banco (finestre congelate + census); il caso dispatch3181 entra direttamente nel router.
- Il census produttori classifica r1 da pool/costante: gli eventi costruiti con shift (es. `mov rX,0x23; asl rX,rX,8` → classe 0x23xx) non sono risolti — gli `asl rX<<8/0xA` trovati producono classi 0x23xx/0x09xx/0x41xx, non 0x3B81/0x3181/0x3301/0x4006 (v. audit per la verifica indipendente).
- **0x4006 resta APERTO**: nessun produttore a costante; la sua consegna (probabile broadcast con evento in registro) non è identificata.
- L'ordine di schedulazione runtime (chi posta 0x3181 rispetto a 0x4405/0x158d04) NON è provato: il banco dimostra i singoli stadi della consegna, non la schedulazione del ciclo.
- La `asr_s` a 0x7F6854 opera su r0 (=pool 0x89A318 >>7 secondo objdump GNU) — non influenza il percorso 0x3181 (nessun uso di r14 dopo il forward) e resta non decodificata nel dettaglio.
- Chiamate indirette statisticamente invisibili; il flusso reale su fotocamera non provato.

## Prossimo passo (non ripetitivo)

(a) **Produttore del broadcast 0x4006 e delle voci 0x4001/0x4002**: cercare chi consegna 0x4006 alle ≥8 finestre (funzione che cammina la lista finestre registrate — candidati: il registro WindowManager con writer di [0x366EA4] e le liste 0x99AAE8/0x99AB40; oppure eventi costruiti in registro passati a 0x169D78 con desc esplicito). (b) In alternativa: decodificare 0x16F920 (query di stato usata dalla macchina tasti del router con id 1/5/6/0x66) per collegare snapshot→coda→router alla macchina tasti già studiata. (c) Lungo corso: chi scrive [0x366EA4] (apertura/registrazione finestra corrente).
