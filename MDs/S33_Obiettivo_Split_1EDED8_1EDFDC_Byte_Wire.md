# Percorso split 0x1EDED8/0x1EDFDC dello switch obiettivo fino ai byte wire: transazione, record multi-slot, query 0x70, bulk 0x80 e marcatori 0xF0/0x55/0xAA

**Correzione23ottobre2026:** [S33_Correzione_Identita_Cluster_25F338_NAND.md](S33_Correzione_Identita_Cluster_25F338_NAND.md). L’attribuzione di25F338/25CBxx–260Dxx al MCU dell’obiettivo è ritirata: percorsi originaliDEVNAND/updater verificati. Questo rapporto conserva byte/formule/provenienza storici; le relative etichette ottiche non sono conclusioni valide.

**Data:** 22 ottobre 2026 (iterazione 12 del ciclo Vibe persistente) · **Tappe:** R0/R1 · **Esito:** PASS statico, chiude il punto aperto (a) dell'iterazione 11, nessun hardware toccato · **Stima complessiva: circa 10 % invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_split_paths.py](../Python_Trace_Scripts/s33_verify_lens_split_paths.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Split_Paths/latest.json](../Risultati/Lens_MCU_Interface/Split_Paths/latest.json) (18 finestre GNU allineate salvate come `window_*.txt`, 46 valori di pool letti dai byte raw, 3 costanti ld.as a scala verificata, modelli Python su tutti i 65.536 valori del campo posizioni)
- Chiude il punto aperto (a) dell'iterazione 11 ([Switch consumatore](S33_Obiettivo_Switch_Consumatore_Campi_Comandi.md)): «byte-verificare 0x1EDED8/0x1EDFDC fino ai comandi wire del dizionario {00,10,30,50,60,70,80,D0,FF}».
- Agente `split-paths-audit` (revisione indipendente, configurazione ereditata): esito in §10.

## 1. Domanda e metodo

Come i due helper dello split dello switch 0x1EE730 — 0x1EDED8 per i casi 1..6 e 0x1EDFDC per il caso 0 — raggiungono il wire, e in quali punti entrano i byte del dizionario. Metodo: finestre GNU ARC700 allineate a ogni ingresso verificato per chiamata (18 finestre), valori di pool riletti come word LE dai byte raw del payload0, costanti `ld.as` verificate con la regola scalata `((PC & ~3) + off*4)`, modelli Python dell'aritmetica (pattern dei record, posizioni degli slot, validatore di risposta, base dei passi, avanzamento dei chunk).

## 2. Dispatch dello split (byte)

In 0x1EE958 (finestra `split_dispatch`): `r14 += r17` (r14 = cmd·cum + arg2); `chunks = ceil(arg3/(ctxA[+0x10]<<9))` via millicode di divisione 0x335B34 (resto in r1; se resto ≠ 0, quoziente+1); **finestra accettata `cmd·param ≥ chunks+arg2`**: `bhs_s` a 0x1EE974 prosegue senza borrow (semantica ARC700: il carry è impostato sul borrow di SUB/CMP, `bhs` = C=0), errore 0x1B00116 quando `cmd·param < chunks+arg2` — **CORREGGE l'iterazione 11**, che aveva la finestra invertita («arg2<cmd·param<arg2+chunks», vedi §10); `chunks==0` → ritorno 0; **casi 1..6 → 0x1EDED8(cmd·cum+arg2, chunks, r15, 0)** con `bl_s` a 0x1EE990; **caso 0** (r16==0): richiede `arg2==0` (a 0x1EE9C4, `cmp r17,0`; altrimenti esce dal tratto), → a 0x1EE9CA: `ctxB[180/184/188/192] = [r15+0/+4/+8/+0xC]` (le quattro word di arg1 nei campi ctxB 0xB4/0xB8/0xBC/0xC0, byte-exact come l'iterazione 11), se una delle quattro è non zero → **0x1EDFDC(0, chunks, puntatore alle 4 word, 0)** a 0x1EEA08, se tutte zero → `ctxB[0xAC] = 0` e uscita con **0x1B00116** (via 0x1EE976); quindi `ctxB[0xAC] = ceil(ctxB[0xB8]/((cmd<<9)·ctxA[+0x10]))` via 0x3342A8/0x335B34, ≤ 0x50 sennò 0x1B00113 (pool 0x1EED6C), e hub 0x1EE148(0,0).

## 3. 0x1EDED8: mossa a passi con loop sui chunk

Finestra `step_move` (0x1EDED8..0x1EDFDC). Header: salvataggio r13–r18 (0x334120), argomenti r18=offset (cmd·cum+arg2), r16=chunks, r13=passo, r17=0; ctxA via 0x25CAEC; **guardia 0x25CFE4 = bit 7 della halfword a 0x50F52E (ctxA+2)**: set → ritorno 0x1B00001 (pool 0x1EE1EC). Poi:

- **0x25C87C(offset)**: preparazione del passo (due divisioni 0x335B34, campi del ctrl, banco 0x36B244 con byte +0x10..+0x14; errore 0x1B00102 pool 0x25CABC).
- **0x25C800** = pronto sse `byte[0x36B255] == 0` (byte di stato del ctrl+1, pool 0x25C878); **0x25C80C** = fine sse `ctrl[+1] == ctxA[+5]-1`.
- Coda d'errore 0x1EDC9C: retry×2 su busy 0x1B0000A con 0x1EDB48/0x1EDC78, finale 0x1B00009; validazione 0x1EDA10 (bit-table 0x50F190 e byte del genitore 0x36B244).
- **Passo singolo 0x1EDD08(offset, extra) = 0x2606B4(offset, 0x50E940, ctrl, extra) + query 0x260C6C**.
- Loop dei chunk: per ogni chunk rimanente `r13 += ctxA[+0x10]<<9` (delay slot di 0x25C80C), pubblicazione LUT 0x1EDD2C, `sub.f r16,1` countdown; uscita per chunks esauriti con 0x1EDE7C (sincronizzazione di stato) e retry 0x25C8F0.

## 4. 0x1EDFDC: multi-step del caso 0, dal record parametro al bulk

Finestra `case0_helper` (0x1EDFDC..0x1EE148). Header: 0x334118, r17=n_steps (chunks), r16=puntatore alle 4 word, r20=0; stessa guardia busy 0x25CFE4 → 0x1B00001. **Gate bit 0xA di ctxA[+2]**: clear → record writer **0x25C1F0** con r19=4; set → **0x25C37C** con r19=2 (i due writer di record già noti dall'iterazione Contesti). Quindi `h(ctrl+2) = h(ctxB+8)` e `h(ctrl+4) = ctxB[196]` (il cumulativo 0xC4). Per ogni passo:

1. `ctrl[+1] = 0`; ready 0x25C800; **bound di indice: `r13 < ctxB[210]+r19`** (il parametro 0xD2 più 2 o 4): `bnc` a 0x1EE066 (C=0, nessun borrow) salta al ramo errore quando `r13 ≥ bound`, cioè **0x1B00108** (pool 0x1EE200) scatta per indice fuori tabella — l'indice serve a leggere `ctxB[8+2·r13]` e deve restare dentro la tabella dei passi;
2. halfword del passo = `ctxB[8+2·r13]` (via `add1_s`), se zero → **0x1B0010A** (pool 0x1EDDFC, caricato con `ld.as` scalato);
3. **0x25F6A4(0x50E940, ctrl)** = scrittura record parametro (byte wire 0x50, iterazione Contesti); attenzione **0x25F28C** (0x00/0xFF);
4. validatore **0x25CBF0(0x50E940)**: richiede `byte[+5]==0xF0` e marcatori 0x55/0xAA a +1/+2/+6/+7 (retry fino a `[record+0] ≥ 7`), sennò r13++ e ripete;
5. **0x29DDD4(ctrl)** = primitiva di movimento (byte wire 0x60/0xD0 con posizione r57 sulla porta 0x0FF05000, iterazione Contesti);
6. query **0x260C6C** (byte wire 0x70); se non pronta, attesa **0x1EDC10** (polling con 0x260AD0 e attenzione 0x25F28C fino a che `ctrl[+1]` raggiunge il byte cmd `ctxA[+5]`, con ripristino dello stato salvato);
7. **aggiornamento LUT: `h(0x50E9C0 + 2·h(ctrl+4)) = halfword del passo`** (la stessa cella 0x50E9C0 usata come LUT nel ramo NAND);
8. reset record **0x25CE18(0x50E940)** (fill 0xFF di count×16 byte) e riempimento posizioni **0x25CF10(0x50E940, ctrl)**: per ogni slot da 16 byte, 0xFF a +4/+5 e posizione `0x1000(bit12)+2·h(ctrl+4)` (sempre pari, arrotondamento difensivo) a +6/+7/+0xB/+0xC;
9. **passo bulk 0x2606B4** con base `((cmd·r18 + ctrl[+1])<<9)·ctxA[+0x10] + r16` (r18 = passi completati), argomenti (base, 0x50E940, ctrl, r20); busy → **0x1B0000A**;
10. query 0x260C6C; avanzamento su 0x25C80C (ctrl[+1]==cmd-1): r13++, r18++, countdown n_steps (`sub.f r17,1`), retry 0x25C8F0.

## 5. I callee del tratto e i byte wire

- **0x1EDB48** (finestra `wire_step`): la transazione vera: se la halfword a 0x3692E8 ≠ 0xFFFF, `0x25F338(buf512=0x50D940, record=0x50E980, ctrl=0x36B254, 0)` con retry×2 (busy 0x1B0000A) e validatori 0x25CBD0 (byte slot +4: 0xFF → errore, 0 → ok, altrimenti 0x29DE80(byte) < 5), 0x25CCA0/0x25CCFC (confronti 3-byte via 0x29DEEC chiamato in registro, pool 0x25D10C; tabelle 0x50F514/0x50F520); altrimenti fill **0x13A954(0x50D940, 0xFF, count<<9)**, reset 0x25CE18(0x50E980), posizioni 0x25CF10, transazione 0x2607B4(0x50D940, 0x50E980, ctrl) e query 0x260C6C. Codici: 0x1B00010/0x1B0000F/0x1B0000A.
- **0x25CFBC** (finestra `query70_alt`): **`mov r0,0x70`** → 0x25CB3C → 0x25E064 (scrittura porta) — iniezione letterale del byte dizionario 0x70; lettura 0x25E08C bit 6; errore 0x1B00007 (pool 0x25D104). Dalla revisione indipendente: i pool di porta **0x25E06C/0x25E080/0x25E094 = 0x0FF05000 raw** — la porta MCU obiettivo confermata a byte su tre punti del sender.
- **0x260C6C** (finestra `query70`): stessa iniezione **0x70** (0x260C78) via 0x25CB3C, lettura 0x25E08C bit 0, errore 0x1B00007.
- **0x2606B4** (finestra `bulk80`): **`mov r0,0x80`** → 0x25CB3C, poi **sender descrittore 0x25CB54(ctrl)**; loop sugli slot: scritture 512-byte a `base+(slot<<9)` via 0x260624 e indirizzo slot `(slot<<4)+record` via 0x260678; invalidazione: byte +4/+5 forzati a 0xFF se non già 0xFF/0xF0; secondo loop via 0x260698. Il byte 0x80 è l'upload bulk a blocchi 512B del dizionario dell'iterazione Wire.
- **0x25CE18(record)**: fill 0xFF di count×16 byte (loop `lp_count=0x10` per slot). **0x25CF6C(record)**: per ogni slot da 16 byte pattern 0xFF con **0xF0 a +5** (idioma `cmp r1,5` / `sub.eq` / `neg` / `bmsk 3` / `+240`).
- **0x25CF10(record, ctrl)**: posizioni = `0x1000 (bit12) + 2·h(ctrl+4)` via `bset 0xc` + `add1_s` (b+(c<<1)), `asr 8` per il byte alto, byte a +6/+7/+0xB/+0xC, 0xFF a +4/+5.
- **0x25CBF0/0x25CC48**: validatori gemelli (soglia `[record+0] ≥ 7` rispettivamente `≥ 2`): `byte[+5]==0xF0(240)` e 0x55/0xAA a +1/+2/+6/+7.
- **0x1EDD2C**: pubblica `h(0x50E9C0 + 2·h(ctrl+8)) = h(0x3692EA)` e sincronizza il mirror 0x3692E8/EA ↔ ctrl (flag word 0x36B250).
- **0x1EDDB4**: recovery dell'anello (validazione 0x1EDA10, mirror 0x36B24C/0x36B250 ↔ 0x3692E8/EA, pubblicazione 0x1EDD2C).
- **0x1EDE7C**: ripete 0x1EDB48 finché `ctrl[+1]` raggiunge `ctxA[+5]`, poi 0x1EDD2C; restore `h(ctrl+2) = h(0x3692EA)`.

Punti di iniezione dei byte dizionario in questo tratto (byte-verified): **0x70** a 0x25CFC4 e 0x260C78; **0x80** a 0x2606DA (seguito dal sender 0x25CB54); **0xFF** (fill 0x25CE18, fill buf512 via 0x13A954, invalidazione slot 0x2606B4); **0xF0** a slot+5 (0x25CF6C) e atteso a record+5 (validatori); **0x55/0xAA** marcatori risposta a +1/+2/+6/+7. I byte **0x50** (0x25F6A4), **0x60/0xD0** (0x29DDD4) e **0x00/0xFF** (0x25F28C) entrano per cross-reference dell'iterazione Contesti (corpi non rieseguiti qui).

## 6. Pool e regola ld.as

46 valori di pool asseriti letti dai byte raw (vinte `verified_evidence.json`): ctrl 0x36B254, genitore 0x36B244, byte di stato 0x36B255, mirror 0x3692E8/0x3692EA, 0x36B24C/0x36B250, record 0x50E940, record passo 0x50E980, buf512 0x50D940, LUT 0x50E9C0, bit-table 0x50F190, celle flag 0x50F52E/0x50F514/0x50F520, guardia 0x50F4D4, template 0x3F668C, tabelle 0x50F514/0x50F520, e i codici 0x1B00001/02/07/09/0A/0F/10/102/108/10A (+ 0x1B00113/116 dell'iterazione 11). I tre `ld.as` costanti dentro 0x1EDFDC risolvono con la regola scalata su 0x1EDDDC=0x36B254, 0x1EDDFC=0x1B0010A, 0x1EDE24=0x50E9C0; **l'annotazione `;0x...` di objdump per ld.as è l'indirizzo NON scalato** (caveat toolchain confermato su tre siti).

## 7. Modelli Python

Pattern per slot (0x25CF6C) = 0xFF×5 + 0xF0 + 0xFF×10, verificato per count 1/2/4/0x10; posizioni (0x25CF10) = 0x1000+2·value sempre pari su tutti i 65.536 valori (l'arrotondamento non può mai scattare); validatore risposta: ok sse `byte[+5]==0xF0` e 0x55/0xAA a +1/+2/+6/+7 con `[record+0]≥7`; base dei passi 0x2606B4 = `((cmd·steps+state)<<9)·count + arg2` multipla di 512 per slot; avanzamento chunk `r13 += count<<9` per chunk (mod 2^32).

## 8. Nuove celle e contesto

0x50D940 (buf512 del passo wire), 0x50E980 (record multi-slot count×16 del passo wire), 0x50E9C0 (LUT condivisa col ramo NAND: scritta da 0x1EDFDC/0x1EDD2C), 0x36B24C/0x36B250 (mirror/flag word del genitore), 0x3692E8/0x3692EA (mirror halfword), 0x50F52E (flag ctxA+2 letti anche da 0x25CFE4 come bit7), 0x50F514/0x50F520 (tabelle di confronto 3-byte di 0x25CCA0/0x25CCFC), 0x3F668C (template, 12 byte prima di 0x3F6698).

## 9. Recupero dell'iterazione 11

La sessione interrotta dell'iterazione 11 aveva completato rapporto, script, evidenze, roadmap, percorsi, Stato_progetto, AGENTS e mappa_ram; mancava la voce nel checkpoint di passaggio consegne (aggiunta dall'iterazione 12 con verificatore Switch_Consumer rieseguito PASS, evidenza 20261021T234156Z). La §9 del rapporto (revisione agente) era rimasta in sospeso: l'agente `switch-consumer-audit` non ha mai restituito output; la revisione indipendente di questa sessione (`split-paths-audit`, §10) copre anche i claim dell'iterazione 11 (claim F).

## 10. Revisione indipendente (agente)

Esito dell'agente `split-paths-audit` (configurazione ereditata; due turni: il primo interrotto dal limite turni, il secondo di verdetto). Lo strumento «task con agente explore» richiesto non esiste in questo ambiente, come già annotato nelle iterazioni precedenti. L'agente ha riverificato i byte raw del payload0, riallineato finestre proprie e confrontato il manuale ARCompact locale per la semantica dei flag; non ha eseguito il verificatore né scritto evidenze.

- **Claim A/B/E/F (dispatch split, 0x1EDED8, ld.as, recuperabile iterazione 11): CONFERMATI.** Per l'iterazione 11 (claim F): jt1/jt2 raw verificati, transazione 0x25F338(0x54D8A8, 0x50E940, desc) con descrittore {0,4,0} a 0x36B254, memcpy 0xAD920(dst=ctxB, src=0x54DAB2, len=0xF4), gemello 0x1ED11C con jt `04 0d 16 1f 28 38 41` a 0x1ED17C e output in [arg4] — la §9 del suo rapporto si chiude qui con esito positivo.
- **Claim C: CONFERMATO** per sequenza, gate e aritmetica (bound, halfword del passo, validatore 0x25CBF0 col corpo aperto, LUT, base 0x2606B4 con doppia mul 0x3342A8, retry 0x25C8F0). I corpi di 0x25CE18/0x25CF10 non sono stati aperti dall'agente entro il suo limite (restano coperti dalle finestre `record_fill_ff`/`record_positions` del verificatore).
- **Claim D: PARZIALMENTE CONFERMATO.** Nuovo fatto byte-verified: **i pool di porta 0x25E06C/0x25E080/0x25E094 = 0x0FF05000** — la porta MCU obiettivo, confermata raw su tre punti del sender 0x25CB3C→0x25E064/0x25E08C. Il qualificatore esatto della store/lettura di porta (halfword `.di` vs word) resta non decodificato del tutto. I corpi di 0x25CFBC/0x260C6C/0x2606B4 non sono stati riaperti dall'agente (coperti dalle finestre del verificatore).
- **CORREZIONE ACCOLTA (claim A/finestra):** la «finestra accettata arg2<cmd·param<arg2+chunks» delle iterazioni 9–11 era **INVERTITA**: con la semantica ARC700 (C=1 su borrow; in binutils `bhs`=F_NOTCARRY, `blo`/`bnc`=F_CARRY) `bhs_s` a 0x1EE974 accetta quando `cmd·param ≥ arg2+chunks`, e l'errore 0x1B00116 scatta per `arg2 < cmd·param < arg2+chunks`. Il verificatore dell'iterazione 11 non copriva la direzione (solo pattern-matching del `bhs`); il verificatore di questa iterazione ora asserisce il ramo e la finestra corretta. Lo stesso ragione è alla base della direzione del bound 0x1B00108 sopra (corretta in §4).
- **Semantica ARC consolidata dall'agente:** ADD1/ADD1_S = b+(c<<1) (manuale; «b+3c» vale solo nel caso degenere add1 r13,r14,r14, sito 0x25CCA0 non aperto); SUB/CMP: C=1 su borrow; `bnc`≡`bhs` (stesso codice condizione); ldw_s/stw_s 16-bit e extw_s zero-extension confermati d'uso.
- **Pool riverificati a byte raw:** 0x1EE9AC/0x1EE9B0/0x1EE9B4/0x1EE9B8/0x1EE9BC/0x1EE9C0/0x1EED6C, 0x1EE1EC/0x1EE1F0/0x1EE1F4/0x1EE1F8/0x1EE200, 0x1EE994/0x1EE998, 0x1EDDDC/0x1EDDFC/0x1EDE24, 0x25C878, 0x25D108, 0x25E06C/0x25E080/0x25E094.

Non verificato dall'agente (e perché): i corpi sopra elencati non aperti entro il limite turni e la variante esatta della store di porta; per questi punti il PASS del verificatore resta l'unica copertura (finestre salvate `window_*.txt`).

## 11. Limiti

- Statico: nessun MMIO, MCU obiettivo o fotocamera toccata; nessun firmware eseguito; NON_INSTALLARE.
- I prodotti dentro 0x1EDFDC passano per il millicode 0x3342A8: esatti solo sotto l'ipotesi MULUDW condizionale documentata (CPU non provata).
- I valori runtime (byte cmd, count, flag, stato ctrl, contenuto mirror/LUT) non sono derivabili staticamente.
- La base di 0x2606B4 nel caso 0 somma il **valore del puntatore alle 4 word di arg1** a `((cmd·steps+state)<<9)·count`: i byte dicono questo, il senso fisico di quella base resta aperto.
- 0x29DEEC (chiamato via registro), 0x260624/0x260678/0x260698, 0x2607B4, 0x2608A8, 0x260AD0, 0x25DF24/0x25DF4C/0x25DF74/0x25DF9C, 0x25DEAC/0x25DEE8 e 0x29DE80 sono cross-riferiti per call site, non byte-decodificati qui.
- La semantica 0x50/0x60/0xD0/0x00 di 0x25F6A4/0x29DDD4/0x25F28C è cross-reference dell'iterazione Contesti, non riderivata.
- V1.1 analizzata vs macchina V1.0: nessun trasferimento automatico di indirizzi.

## 12. Prossimo passo (non ripetitivo)

(a) Byte-decodificare il sender 0x25CB3C/0x25DF24/0x25E064 fino alla sequenza di halfword sulla porta 0x0FF05000 e al gate/strobe, per chiudere il tratto byte wire → segnale fisico (chiude i residui 0x25DFxx/0x25DExx); (b) in alternativa, i lettori/scrittori Main del banco 0x0FE400xx partendo da 0x301EC0 (identità periferica, aperto dall'iterazione 8). Entrambe offline e byte-verificabili.
