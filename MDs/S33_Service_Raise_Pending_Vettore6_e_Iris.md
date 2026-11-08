# Service-request framework — lato raise dei pending: il trigger del vettore 6 è solo hardware; router a classi alte e tabelle di servizio ottava/nessa

**Iterazione 38 — 1 novembre 2026 — studio offline statico (payload0/payload1 V1.1).**
Verificatore: [s33_verify_service_raise_pending.py](../Python_Trace_Scripts/s33_verify_service_raise_pending.py).
Evidenza: [cartella 20261101T102211Z](../Risultati/Runtime_Kernel/Service_Raise_Pending/20261101T102211Z/) (`verified_evidence.json`, snapshot script, 26 finestre GNU allineate `window_*.txt`).

## 1. Domanda affrontata

Prossimo passo (a) dell'iterazione 36 ([checkpoint](S33_Vibe_Offline_Checkpoint.md)): chi alza a runtime i bit pending — i tre chiamanti di 0x16D4D8 (per gli id passati) e il sito LE 0x1A14A8 = 0xFED3818 — per attribuire l'evento fisico che pilota il vettore 6 (pending 0xFEF0074, id 0x610 della tabella 0x424B18) e la richiesta iris 0x3002 (pending 0xFED3818 bit 2).

## 2. Il raise generico 0x16D4D8 e i suoi tre chiamanti: chiamate destinate a fallire

0x16D4D8(id) ricerca l'id nelle **sei tabelle generiche** dell'array 0x3F6CC8 ({0x424A00, 0x424A8C, 0x424B18, 0x424BA4, 0x424C30, 0x424CBC}) e confronta il registro r0 **a 32 bit completi** contro l'id halfword del record (`cmp_s r0,r3` a 0x16D500; record a table+12+8k, `add3_s` scala 8, `ldh.di [r3,12]`; nessuna istruzione di maschera su r0 nella finestra 0x16D4D8..0x16D5B6). Al match: sezione critica 0x1786E8, `sth.di 1<<bitB` sul pending halfword puntato da [table+0], 0x179354; senza match ritorna il codice pool 0x16D6D0 = **0x200601**.

I **tre chiamanti statici** (census congelato) passano costanti a 32 bit con halfword alta 0xFFFF, caricate nei delay slot:

| Sito bl.d | Delay slot | Pool | Id passato |
|---|---|---|---|
| 0x16F0F6 (funzione 0x16F0EC) | ld_s 0x16F0FA → 0x16F11C | 0x16F11C | **0xFFFF9007** |
| 0x2331B4 (funzione 0x2331B0) | ld 0x2331B8 → 0x2331AC | 0x2331AC | **0xFFFF8008** |
| 0x238B56 (ramo arg==2 di 0x238B34) | ld_s 0x238B5A → 0x238B68 | 0x238B68 | **0xFFFF800B** |

Gli id dei record delle sei tabelle (84 record totali) stanno in 0x0401..0x0A10 (parse payload1; gli id 0x6001..0xB00D delle tabelle di classe alta, §4, sono fuori dall'array e mai confrontati dalla raise): un id 32-bit con halfword alta 0xFFFF **non può mai eguagliare** un id halfword. Modello funzionale nel verificatore: per i tre id la raise ritorna sempre 0x200601; il controllo positivo raise(0x610) settebbe il bit 15 di 0xFEF0074. **Il valore di ritorno è ignorato in tutti e tre i siti** → le tre chiamate raise sono no-op a runtime.

Gli stessi costanti SONO id validi per i router enable/register (classe = id & 0xFF00 → 0x9000/0x8000, argomento servizio = id & 0xFFFF): la coppia di funzioni 0x2331A0/0x2331B0 usa 0xFFFF8008 rispettivamente per 0x16D898 (register) e per la raise fallimentare seguita dal servizio reale 0x266380(0x8008); l'init lens 0x23912A usa 0x800B per il register di classe alta 0x266444. La lettura più coerente è che il servizio di trigger effetivamente usato sia quello di classe (§4), e le tre raise siano residui/erie di refactoring: nessuna asserzione indebolita, il fallimento è byte-provato.

Fondamenta ISA/codifica (verificate in sessione): `CMP_S b,h` = confronto 32-bit completo (manuale ARCompact, outputs/arc700_public_references/ARCompact_5115-029.pdf); `ld` semplice = NON scalato (bytes f4 17 00 f0 a 0x2331B8, confronto encoding con arc-elf32-as: `ld.as` = f6, `ld` = f0); `ld_s [pcl,off]` target = (PC&~3)+field×4 (riconfermato su 0x241E9C→0x241F7C=0x3002 e 0x16D406→0x16D50C=0x2640E0).

## 3. Il trigger del vettore 6 è alzato solo dall'hardware

Scansione completa payload0 di word LE verso 0xFEF0074 (pending del vettore 6): **esattamente tre siti pool**, tutti non-raise:
- 0x263F30 — dentro il W1C clear-all 0x263F08 (chiamato dall'init framework 0x16D3F0): scrive 0xFFFF su una sequenza di pending (0xFEF0050/0xFEF0328/0xFEF0074/0xFEF003C/0xFEF0040/0xFEF0044);
- 0x2640B8 — getter del bit 9: `ldh.di; lsr_s 9; bmsk_s 0` (id 0x609);
- 0x2640D4 — W1C clear del bit 9: `sth.di 0x200`.

Il walker 0x264250 legge la 0xFEF0074 via LIMM assoluti e fa W1C del bit servito (iterazione 36). Nessun scrittore software di bit pending esiste: **il bit 15 (id 0x610, la callback che invoca il dispatcher nidificato 0x242488 → 0x241E5C → 0x140704) è alzato solo dall'hardware** (controllore interrupt 0xFEF0xxx). Anche la scansione dei limm middle-endian verso 0xFEF0074 in payload0 (pattern EF 0F 74 00, convenzione limm confermata sul byte `00 00 00 ff` di `and r1,r0,0xff00` a 0x16D5C4; zero occorrenze anche in big-endian) dà **zero occorrenze** (audit raise-audit-38b): nessun riferimento alternativo da classificare. Il framework service-request è interamente guidato da interrupt: software arma (enable) alla registrazione, hardware alza (pending), i walker consumano.

## 4. Router 0x16D5BC: classi alte e servizi diretti; tabelle di servizio fuori dall'array

Il router 0x16D5BC(id, flag) calcola la classe con `and r1,r0,0xff00`. Mappa completa decodificata (finestra 0x16D5BC..0x16D7E8):
- classi **0x3000/0x4000** → 0x2422e8/0x242380 (famiglia iris, iterazione 36);
- classi **basse 0x0400/0x0500/0x0600/0x0800/0x0900/0x0A00** → sei tabelle generiche (enable [table+4] bit bitA set/clear per flag; confronto id a 32 bit);
- classi **alte 0x1000/0x2000/0x5000/0x6000/0x7000/0x8000/0x9000/0xA000/0xB000** → servizi diretti per classe con `extw_s r0` (id & 0xFFFF) nei delay slot: 0x1000→0x26671c/0x2667b0, 0x2000→0x265fe8/0x26605c, 0x5000→0x2668d8/0x266940, 0x6000→0x266170/0x2661d8, 0x7000→0x24d388/0x24d3f0, 0x8000→0x266380/0x2663ec, 0x9000→0x266af0/0x266b5c, 0xA000→0x266d0c/0x266d74, 0xB000→0x26658c/0x2665f4 (coppie flag≠0/flag==0);
- classe ignota → pool 0x16DB20 = 0x200601 (la classe bassa 0x0700 rimane assente, come da audit svc-framework-audit-36; 0x7000 è la classe ALTA).

Esemplare classe 0x6000 (0x266170, flag≠0): richiede (arg & 0x6000) == 0x6000; alla prima chiamata (gate cella 0x36B330) registra il watchdog **0x16D898(0x90D, 0x26627C)** e lo abilita (0x16D7E8(0x90D, 0xFF)) — id 0x90D della tabella 0x424C30, classe 0x0900, vettore 9 —; setta un bit di gate ((arg&0x1F)−1); poi **0x2660E8(mask, flag)** ricerca una **SETTIMA tabella statica 0x424E00** (payload1: pending **0xFEF0228**, enable **0xFEF022C**, 16 record id 0x6001..0x6010, bit 15..0) e setta il suo pending (e enable per flag). **0x424E00 non è nell'array 0x3F6CC8**: le classi alte hanno tabelle dedicate con MMIO propri.

Tabella classe 0x8000: 0x266300 cerca **0x424F00** (pending 0xFEF0048, enable 0xFEF0324, id 0x8001..0x8010); il **register di classe alta 0x266444(id, fn)** scrive fn nel record (`st.di [r1,16]`); esiste anche **0x425000** (pending 0xFEF044C, enable 0xFEF0448, 13 record id 0xB001..0xB00D) per la classe 0xB000. Riferimenti pool LE in payload0: 0x424E00 = {0x266120 (raiser 0x2660E8), 0x26629C (register/watchdog 0x26627C)}, 0x424F00 = {0x266330 (raiser 0x266300), 0x2664A0 (register 0x266444)}.

## 5. Sito 0x1A14A8 (0xFED3818): l'handler 0x3004 che accusa il pending iris e polla il banco strobe

L'unico riferimento pool LE a 0xFED3818 (pending famiglia iris) in payload0 è **0x1A14A8**, dentro la funzione **0x1A1490**, registrata sotto **id 0x3004** dalla init 0x1A082C (gate byte 0x368500; `0x242414(0x3004, 0x1A1490)` + `0x2422e8(0x3004)`; chiamanti census {0x1A0AA2, 0x1A1474}). Corpo (finestre 0x1A1490..0x1A14F0):
1. `sth.di r15,[r0]` con r15=1 e r0=0xFED3818 → **W1C acknowledge del bit 0 = id 0x3004, il proprio** (tabella 0x424500: 0x3007→bit 6, 0x3006→5, 0x3005→4, 0x3001→3, 0x3002→2, 0x3003→1, 0x3004→0; correzione dell'audit raise-audit-38b alla prima stesura che indicava 0x3001): l'handler "riconosce" il proprio interrupt;
2. legge **0xFED18C8** (stato) e **0xFED18CC** (maschera) del banco strobe (0xFED1xxx, stessa banca dei registri strobe 0xFED18A0/AC/B0), calcola `a & b & 0xF`, e se non zero invoca il callback `jl_s [[0x368510]]`;
3. prosegue con coppie status/mask 0xFED1910/0xFED1914/0xFED1918 (maschera 0x1DF sul resto).

La mappa delle registrazioni famiglia iris (tabella 0x424500) risultacompleta:
- **0x3002 → 0x241E5C** (iterazione 34; registrato da 0x241E94);
- **0x3004 → 0x1A1490** (questa iterazione);
- **0x3001 → 0x23915C** (famiglia lens: helper registro 0x23914C `b.d 0x242414` con delay `ld_s → 0x239158 = 0x3001` e fn pool 0x239154 = 0x23915C; ready wrapper 0x23917C, unregister 0x239194; census ready {0x238D02, 0x238D10}, unreg {0x238662, 0x238BE6, 0x238D32, 0x238D4A, 0x238D92}).

L'init lens 0x23912A registra anche l'**handler 0x238C88 sotto id 0x800B della tabella alta 0x424F00** (via 0x266444; fn pool 0x239148), pubblica l'evento 0x200000C bit 0, e l'handler 0x800B 0x238C88 incrementa un contatore e chiama 0x238B34 — il terzo chiamante della raise fallimentare. Il pending 0xFED3818 (incluso il bit 2 della richiesta 0x3002) resta quindi scritto dal software SOLO tramite il request setter 0x242224 armato al ready (0x2422e8, "kick" iniziale che processa lo stato corrente) e azzerato via W1C dal dispatcher e dall'handler 0x3004; le ripetizioni successive nascono dall'hardware del controllore 0xFED3xxx.

## 6. Comandi/esiti

- `python3 Python_Trace_Scripts/s33_verify_service_raise_pending.py` → **PASS_SERVICE_RAISE_PENDING_STATIC 20261101T102211Z** (exit 0): sha firmware + blocchi, 27 pool LE raw, parse delle tabelle 0x424B18/0x424E00/0x424F00/0x425000 e array 0x3F6CC8, 26 finestre GNU ARC700 allineate con pattern congelati, 11 scansioni LE con attese congelate, census bl di 8 target, modello funzionale della raise (3 id fallimentari + controllo 0x610).
- Prove ISA in sessione: `pdftotext` del manuale ARCompact (CMP_S b,h = b−h, confronto 32 bit); `arc-elf32-as` + `objdump -d` del confronto `ld`/`ld.as [pcl,-12]` (encoding f4 17 f0 00/f6: il sito 0x2331B8 è `ld` semplice non scalato).
- Agente di revisione indipendente **`raise-audit-38b`** (tools.agents.spawn, «task con agente explore» non esiste in questo ambiente, come documentato): ha rieseguito il verificatore → **PASS identico 20261101T102314Z** (nuova cartella evidenza della riesecuzione, `latest.json` aggiornato dallo script stesso; comportamento previsto), contatori identici 26/27/11/8. **Claim C1–C4 CONFERMATI byte-exact**; correzioni accolte e applicate in §2/§3/§5: (1) il bit 0 di 0xFED3818 è l'id 0x3004 (il proprio), non 0x3001 — mappa bit della 0x424500 citata; (2) scansione limm middle-endian verso 0xFEF0074 = zero occorrenze in payload0 (convenzione limm verificata sul byte di `and r1,r0,0xff00`), aggiunta a §3; (3) specificati i 84 record delle sei tabelle. Nessuna asserzione indebolita. Il primo tentativo `raise-audit-38` era stato terminato dal limite turni senza esito (documentato).

## 7. Fonti precise

Payload0 base 0x0AD800: raise 0x16D4D8..0x16D5B6 (pool 0x16D580=0x3F6CC8, errore 0x16D6D0=0x200601); chiamanti 0x16F0EC..0x16F118 (pool 0x16F118/0x16F11C/0x16F120), 0x2331A0..0x2331C8 (pool 0x2331A8/0x2331AC), 0x238B34..0x238B6C (pool 0x238B68); router 0x16D5BC..0x16D7E8 (pool 0x16D6D4..0x16D6E8, 0x16DB20=0x200601); servizi classe 0x266170..0x2661D8 (pool 0x26628C..0x266298), 0x2660E8..0x266150 (pool 0x266120), 0x266300..0x266354 (pool 0x266330), 0x266444..0x266482 (pool 0x2664A0), 0x2663EC..0x26643E; W1C 0x263F08..0x263F44 (pool 0x263F14..0x263F3C), getter/clear bit 9 0x2640B0..0x2640E0 (pool 0x2640B8/0x2640D4); handler iris 0x1A1490..0x1A14F0 (pool 0x1A14A0..0x1A14E8), init 0x1A082C..0x1A0864 (pool 0x1A0880..0x1A088C); init lens 0x23912A..0x239146 (pool 0x239148/0x239154/0x239158), handler 0x3001 0x23915C..0x239178, ready/unregister 0x23917C/0x239194; handler 0x800B 0x238C88..0x238CC8. Payload1 base 0x360800: array 0x3F6CC8; tabelle 0x424B18, 0x424E00 (0xFEF0228/0xFEF022C), 0x424F00 (0xFEF0048/0xFEF0324), 0x425000 (0xFEF044C/0xFEF0448).

## 8. Limiti

Statico; nessun hardware/runtime; NON_INSTALLARE; circa10% invariato. L'identità fisica dei controllori 0xFED3xxx/0xFEF0xxx resta aperta (inferenza: controllori interrupt). La semantica W1C dei pending è inferenza forte dal pattern (init scrive 0xFFFF; il servizio riscrive il bit servito). I walker delle tabelle alte (0x424E00/0x424F00/0x425000) non sono stati decodificati: quale vettore serva le classi alte è APERTO (candidati: 0x2643C0 legge [0x423B10] via LIMM — struttura a callback singolo, vettore 7 a doppio installatore con TIMER1; 0x2643E0 cammina 0x424BA4, vettore 8). I restanti corpi dei servizi di classe alta (0x1000/0x2000/0x5000/0x7000/0x9000/0xA000/0xB000) e la tabella di classe 0x9000 non decodificati. Le tre raise fallimentare restano senza spiegazione d'intento (residui o errore): il dato di fatto è il no-op. V1.1 campione vs macchina V1.0.

## 9. Prossimo passo (non ripetitivo)

(a) **Chi serva le tabelle di classe alta**: decodificare i walker candidati (0x2643C0 con LIMM 0x423B10, 0x2643E0 su 0x424BA4, 0x264498) e la struttura 0x423B10, per chiudere la mappa vettore→tabella del framework e il doppio installatore del vettore 7 (punto aperto iterazione 36/29). (b) In alternativa il gemello TIMER0/scheduler tick (punto (b) dell'iterazione 29, sempre aperto). Entrambi offline e byte-verificabili; il punto raise/pending è CHIUSO, non rieseguire i census già fatti.
