# Cella «modalità desiderata» 0x3657C8: produttore identificato nella funzione di salvataggio 0xD0478, blocco contesto 0x3657C8..0x3657D4 e restore 0x7F9F7C — 1 novembre 2026 (iterazione 42)

## Domanda

Punto aperto (a) dell'iterazione 41 ([rapporto](S33_GUI_Transizione_Modalita_Censimento_Chiamanti_CPU_20261101.md)): la cella **0x3657C8** (struct 0x365750+0x78, stessa struct della guardia a +1 e del flag 0x36580C a +188), letta dal getter `0xD0528` e passata da 15 feeder alla transizione di modalità `0xCA404`, non aveva alcuno scrittore statico identificato. Il produttore runtime era APERTO, con la lezione documentata che i census di writer devono coprire anche basi pool vicine con offset piccoli, non solo il pool esatto della cella. La sessione precedente aveva costruito il verificatore ma fu interrotta prima dell'esecuzione finale; il suo run 13:24Z restò `status=RUNNING` senza `verified_evidence.json` e la correzione del getter `0xD0518` (docstring 13:26Z) non fu mai eseguita. Questa iterazione esegue, chiude e audita quella verifica.

## Verificatore ed esiti

- Script: `Python_Trace_Scripts/s33_verify_capture_desired_cell_producer_cpu.py` (statico byte-esatto + 4 casi CPU con byte firmware originali; un solo commento interno obsoleto del tentativo interrotto corretto prima dell'esecuzione: pool del getter `0xD0518` = 0xD04CC, non 0xD0514).
- `python3 Python_Trace_Scripts/s33_verify_capture_desired_cell_producer_cpu.py` → **PASS_CAPTURE_DESIRED_CELL_PRODUCER 20261101T123804339327Z**; riesecuzione indipendente → **PASS_CAPTURE_DESIRED_CELL_PRODUCER 20261101T123843298972Z** (asserzioni e casi byte-identici; `static_evidence.json` identici a meno di `utc`).
- [Evidenze](../Risultati/GUI_S33/capture_desired_cell_producer_cpu_20261101T123804339327Z/) (`verified_evidence.json`, 69 file, 4 casi CPU con ELF/assembler/linker script/log); [riesecuzione](../Risultati/GUI_S33/capture_desired_cell_producer_cpu_20261101T123843298972Z/). I run interrotti della sessione precedente (1219–1224Z) restano archiviati come tentativi, NON come prova.
- Regressioni rieseguite tutte PASS: guard setter census **20261101T123949856825Z**, flag mode matrix 14 casi **20261101T124002005140Z**, snapshot record init 4 casi **20261101T124002508343Z**, service raise pending **20261101T124003Z**.

## Risultato 1 — il produttore è la funzione di salvataggio 0xD0478: la cella è uno SNAPSHOT della modalità corrente

La funzione `0xD0478` (payload0, base 0xAD800) salva l'intero blocco contesto `0x3657C8..0x3657D4` della struct 0x365750 quando il contesto di scatto viene messo da parte. Finestra 0xD0478..0xD04C7 byte-esatta congelata:

| cella | larghezza | produttore del valore | sito store |
|---|---|---|---|
| 0x3657CA | word | `bl 0xDE6D0` | `stb_s r0,[r1,0]` poi parte alta |
| 0x3657D0 | byte | `bl 0xDE398` | `stb_s r0,[r13,0x10]` |
| 0x3657D4 | word | `bl 0x14A1F8`, **clamp ≤ 400** (`cmp r0,400` + re-store) | `st_s r0,[r1,8]` con r1=0x3657CC |
| 0x3657CC | byte | getter guardia `bl 0xCA310` (guardia salvata) | `stb_s r0,[r13,0xc]` |
| 0x3657CD | byte | `bl 0x17E238` | `stb_s r0,[r13,0xd]` |
| 0x3657CE | byte | `bl 0x17E460` | `stb_s r0,[r13,0xe]` |
| 0x3657CF | byte | `bl 0xDEBE8` | `stb_s r0,[r13,0xf]` |
| **0x3657C8** | byte | **cella modalità corrente 0xC8E80C** via `ld_s r0,[pcl,0x1c]` a 0xD04BE (EA=(0xD04BE&~3)+0x1c=0xD04D8, pool 0xD04D8=0xC8E80C) + `ldb_s` | **`stb_s r0,[r13,0x8]` a 0xD04C2**, r13 = pool 0xD04D0 = **0x3657C0** |

Coda: `b 0xCA2CA` a 0xD04C4 → epilogo comune millicode 0x33419C. La cella «desiderata» è quindi una **copia della modalità di scatto corrente presa al momento del salvataggio del contesto** — il nome «ultima modalità di scatto» dell'ipotesi it.41 è coerente; «desiderata» nel senso di «modalità a cui tornare».

**Unicità writer (ambito dichiarato):** scansione listing-wide con tracking dei registri invalidato a ogni prologo/other-write (167 pool con valore in [0x365740..0x365860], 163 store con EA in finestra): **l'unico store con EA 0x3657C8 è 0xD04C2**. Limiti espliciti invariati: writer via puntatori passati in registri attraverso chiamate, o via aritmetica non-pool, NON sono esclusi dalla scansione statica.

## Risultato 2 — il salvataggio avviene uscendo dal modo di scatto: 5 chiamanti, 4 dei quali escono esplicitamente

Census esatto dei chiamanti `bl` di 0xD0478: **5** — 0x20ED7A (p0), 0x65602C, 0x65C3D4, 0x66361A (p2), 0x8021FE (p4).

| sito | classe verificata |
|---|---|
| 0x65602C, 0x65C3D4, 0x8021FE | `save` → `mov r0,3` + `bl 0xCA404` (transizione immediata al **modo 3**) |
| 0x65C3D4 | poi anche `bl 0xCBDF8` |
| 0x66361A | catena di uscita: `bl 0xCB5E4` → `0x145C3C` → `0xCBDF8` → `0x177030` |
| 0x20ED7A | notifica evento 0x7E: `mov r0,0x7e; mov r1,0; bl 0x1453e4` |

Quattro dei cinque siti abbandonano esplicitamente il modo di scatto dopo il salvataggio. La schedulazione/reachability runtime dei cinque siti NON è provata.

## Risultato 3 — getter del blocco e restore 0x7F9F7C (p4)

I sette getter compatti del blocco (mapping verificato dall'encoding: EA=(PC&~3)+imm): `0xD04DC`(byte 0x3657CC), `0xD04E8`(0x3657D0), `0xD04F4`(0x3657CD), `0xD0500`(0x3657CE), `0xD050C`(0x3657CF), **`0xD0518`(WORD 0x3657D4)**, `0xD0520`(word 0x3657CA), oltre al già noto `0xD0528`(0x3657C8).

- **Sei dei sette hanno ESATTAMENTE un chiamante `bl`, tutti dentro la funzione di restore `0x7F9F7C`** (p4): la catena legge 0x3657CA→`0xCE1EC`, 0x3657D0→`0x17C5E4` (r1=r2=−1), `0x14A900(0x64)`, WORD 0x3657D4→`0x163D6C`, 0x3657CD→`0x17E124`, 0x3657CE→`0x17E36C`, 0x3657CF→`0xDEBCC`.
- **Il settimo, `0xD04DC` (guardia salvata), ha il suo unico chiamante a 0x7F6AE6, fuori dal restore**, nel contesto adiacente 0x7F6ADE: la guardia salvata viene copiata in `[pool 0x7F6E20]+0x18` = 0x89A330 (il ramo parallelo a 0x7F6AE2 azzera prima la stessa cella).
- `0xD0528` conferma i 21 chiamanti it.41: 15 feeder di 0xCA404 + 6 consumer di contesto (0x252C0E cmp 0x6A; 0x25327A cmp 0x6A gated 0x163EB4; 0x7F6AF4 cmp 0x1F→0x131544 ff; 0x7F8ACC e 0x7FBE3A cmp 0xA selezione risorsa; 0x7FAA50 cmp 0x37 coppia di ritorno).

## Risultato 4 — CPU: copia originale, store r13+8, e correzione dell'EA del getter 0xD0518

Quattro casi sul simulatore GNU ARC700 con **byte firmware originali** (finestra 0xD04BE..0xD04DB, roundtrip verificato su ogni ELF):

1. `save_mode_46`: fixture cella modalità 0xC8E80C=0x46, r13=0x3657C0 → la sequenza originale copia 0x46 in 0x3657C8 (fault probe `0xdead0046`); vicini 0x3657C7/0x3657C9 intatti (sentinelle 0xA5).
2. `save_mode_2c`: stesso con modalità 0x2C → `0xdead002c`.
3. `save_r13_scratch` (controllo negativo): r13 rediretto su scratch 0x366000 → la cella **conserva la sentinella 0xA5** (fault `0xdead00a5`): lo store è `r13+8`, non un indirizzo fisso; il redirect del banco non falsifica la cella.
4. `getter_d0518_ea`: sonda del getter 0xD0518 con blocco marcato (word 0x3657D4=0x00005DD4) → fault `0xdead5dd4`: la `ld r0,[pcl,-76]` (bytes `b4 17 00 f0`) risolve EA = 0xD0518−76 = **pool 0xD04CC = 0x3657D4** e carica la **WORD** salvata. **Correzione della sessione interrotta**: il pool 0xD0514 (0x3657CF) appartiene al getter 0xD050C; la lezione it.40 sull'EA `ld.as` si estende alla forma 32-bit allineata (EA = PC + imm, PC 4-allineato).

## Audit indipendente

Agente `desired-cell-audit` (tools.agents.spawn; «task con agente explore» non esiste in questo ambiente, come già documentato in it.41). Metodo indipendente: hash dei 16 blocchi contro manifest, ridisassembly ex-novo di tutti i 16 payload con la toolchain arc-elf32, dataflow proprio con propagazione mov/add/sub, regex con confronto esatto del valore (scartando i falsi positivi `;0xd04780/8a/8c` della regione p9).

- **C1–C7 CONFERMATI, C8 nessun controesempio**: nessun secondo getter di 0x3657C8 (valore u32 in un solo sito su 16 payload, allineato), nessun `[rN,0x78]` con base tracciabile a pool in finestra fuori da p0, nessun bl non standard né jump table verso 0xD0478/getter, nessun limm con immediato 0x3657xx, 3004 `jl` tutti a registro senza letterali verso questi indirizzi.
- **Due correzioni documentali accolte e riverificate**: (1) le basi corrette sono payload2 = **0x5FE800** e payload4 = **0x796800** (p0 = 0xAD800), verificate su `verified_payloads`; lo script verificatore non contiene affermazioni di base errate. (2) il chiamante unico di 0xD04DC è **0x7F6AE6, fuori dal restore 0x7F9F7C**: nel rapporto la catena di restore è attribuita solo ai sei getter effettivamente dentro 0x7F9F7C (v. Risultato 3).
- L'agente non ha rieseguito il verificatore (istruzione esplicita); le proprietà dinamiche restano quelle congelate nei 4 casi CPU.

## Fonti precise

Payload0 (base 0xAD800): save 0xD0478, store 0xD04C2, ld_s 0xD04BE, pool 0xD04C8/0xD04CC/0xD04D0/0xD04D4/0xD04D8/0xD0530, getter 0xD04DC..0xD0528, epilogo 0xCA2CA→0x33419C; caller p0 0x20ED7A (0x1453E4). Payload2 (base 0x5FE800): caller 0x65602C, 0x65C3D4, 0x66361A (0xCB5E4/0x145C3C/0xCBDF8/0x177030). Payload4 (base 0x796800): caller 0x8021FE; restore 0x7F9F7C; contesto guardia salvata 0x7F6ADE..0x7F6AF0 (pool 0x7F6E20=0x89A318); non-feeder 0x7F6AF4, 0x7F8ACC, 0x7FAA50, 0x7FBE3A. Payload1 (base 0x360800): byte statico 0x3657C8 = 0x2C.

## Limiti e non-dimostrato

- Statico + 4 casi CPU sintetici; nessun hardware, USB, SD, rendering, scatto. Circa 10% invariato.
- Writer via puntatori passati in registri attraverso chiamate o aritmetica non-pool non esclusi (ambito della scansione dichiarato).
- I 5 chiamanti del save e i chiamanti del restore non sono censiti qui: **schedulazione runtime non provata**.
- Consumer del restore 0xCE1EC/0x17C5E4/0x14A900(0x64)/0x163D6C/0x17E124/0x17E36C/0xDEBCC **non decodificati**.
- La prova CPU usa fixture per 0xC8E80C e per il blocco salvato; non prova il comportamento della fotocamera reale.

## Prossimo passo

Chiudere il ciclo save/restore della modalità di scatto: census dei chiamanti `bl` della **funzione di restore 0x7F9F7C** (p4) e del suo gemello di contesto 0x7F6ADE/0x7F6AE6, classificando gate e condizioni — in particolare se il restore è raggiunto rientrando nel modo di scatto (es. dal modo 3 in cui i tre caller `save_then_mode3` collocano la macchina) e quali consumer (0xCE1EC, 0x163D6C con la word ≤400, 0xDEBCC) ricevono i valori salvati. Questo collega direttamente il blocco ora verificato con la transizione 0xCA404 e i suoi 15 feeder.
