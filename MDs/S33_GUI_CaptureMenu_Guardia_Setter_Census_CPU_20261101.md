# Guardia CaptureMenu: censimento del setter 0xCA2F4, transizione 0xCA404 e cella flag 0x36580C — 2026-11-01

Chiusura del lavoro interrotto delle sessioni precedenti (iterazione 40, due round terminati senza output: uno durante l'attesa dell'agente di audit, uno durante le regressioni; mancavano audit e documentazione). In questa sessione il verificatore è stato rieseguito per intero, non assunto; l'audit è stato rifatto con un agente nuovo (`guard-audit-42`, esito integrato in fondo). Tutto statico sul dump V1.1 più due casi CPU sintetici; nessuna fixture di firmware, nessuna modifica a originali.

## Domanda

Chi può portare la guardia `0x365751` a 7 — la condizione che in modalità `0x2C` mantiene selezionabili le voci `0x0A`/`0xBB` della lista `0x4801` (matrice dell'[iterazione 39](S33_GUI_CaptureMenu_Flag_Produttore_Matrice_Modalita_CPU_20261101.md), punto aperto (a)) — e come la guardia si coordina con la cella modalità `0xC8E80C` letta dal getter `0xCAD30`.

## Risultato

### 1. Corpi e censimenti congelati

`0xCA2F4(v)` scrive solo il byte `v` in `[pool 0xCA30C] = 0x365751` (`ld_s r1,[pcl,0x10]` + `stb_s r0,[r1,0]`); `0xCA310` legge la stessa cella (`ld r0,[pcl,-4]` sul medesimo pool + `ldb_s r0,[r0,0]` + `j_s [blink]`). Censimento `bl` sul listing GNU lineare (metodo regex su `Risultati/Disassemblati/Firmware1.1.asm`, congelato nel verificatore e confrontato con liste esplicite):

| Target | Chiamanti bl | Payload 0 | Payload 2 | Payload 4 |
| --- | --- | --- | --- | --- |
| setter `0xCA2F4` | 27 | 4 | 12 | 11 |
| getter `0xCA310` | 58 | 11 | 41 | 6 |
| transizione `0xCA404` | 63 | — | — | — |
| getter modalità `0xCAD30` | 434 | — | — | — |

### 2. I 27 siti del setter: provenienza di r0

Finestre byte-esatte per ogni sito (classificazione congelata, 27/27):

| Sito | Payload | Classe r0 |
| --- | --- | --- |
| 0xC9DEA | 0 | const0 + teardown flag (vedi §4) |
| 0xCA4A8 | 0 | const0 (leave, nuova modalità ≠ 3) |
| 0xCA4BE | 0 | **const7 (restore: unico sito statico con 7)** |
| 0x20F440 | 0 | const0 se guard ≠ 7 |
| 0x653E02, 0x654E84 | 2 | const3 se guard == 4 (siti che scrivono 3) |
| 0x653F98, 0x654158 | 2 | const0 |
| 0x6543EE, 0x657B4A, 0x7F87BC, 0x7F9BF4 | 2/4 | const0 con gate locale |
| 0x659580 | 2 | identità: riscrive la guardia letta e la copia anche in `0x681F5C+9` (pool 0x659594) |
| 0x65C19A, 0x65CB2A | 2 | const0 se guard ≠ 7 |
| 0x6648C4, 0x664938, 0x6649A4 | 2 | calcolati via `0x631DB8`/`0x631DD0`/`0x631DE8`, se byte `[r15+0xA] == 3` |
| 0x7D7D08 | 4 | const0 se guard == 1 |
| 0x7F76B2, 0x7F86E6 | 4 | const0 |
| 0x7F7F04, 0x7F7FDE, 0x7F8578 | 4 | calcolato: byte `[x,52]` |
| 0x7F8694, 0x7F8764 | 4 | calcolato: byte `[0x89A330]` |
| 0x7F83C4 | 4 | calcolato: `extb(0x6410F4)` dopo lookup risorsa `0x145654(a, 0x4817)` |

Risultato chiave: l'unico sito che scrive **staticamente** 7 è il restore `0xCA4BE` dentro la transizione `0xCA404`; 3 arriva solo dai due siti condizionati a guard==4; i 9 siti calcolati non sono limitati a un insieme di valori e potrebbero produrre 7 in stati di menu non determinabili staticamente (limite esplicito, non controesempio).

### 3. 0xCA404 è la funzione di transizione della modalità di scatto

Finestra `0xCA404..0xCA4C0` verificata byte per byte; dopo i servizi preliminari (`0x33412c`, `0xCADAA8`, `0xCA5DC`, `0xCA6FC`) e i casi speciali (mode `0x38`, `0x6C`/`0x6E`, `0x5`, `0x7D`), il nucleo guardia/modalità è:

1. carica `0xC8E80C` via pool `0xCA5D0` in `r13` (0xCA416); `r13` non ha scrittori fra 0xCA416 e 0xCA4AE (censimento nella finestra);
2. se argomento (nuova modalità) == byte corrente → salta tutto (0xCA486);
3. se corrente == `0x2C`: **salva** `(guard == 7)` come byte 1/0 in `0x365750+188 = 0x36580C` (store `stb r0,[r1,188]` a 0xCA496/0xCA49E, base pool `0xCA5D4`);
4. se nuova modalità ≠ 3: **azzera la guardia** (0xCA4A8, setter con 0);
5. **memorizza la nuova modalità** in `0xC8E80C` a 0xCA4AE (`stb_s r14,[r13,0]`);
6. legge il flag salvato a 0xCA4AA e, se flag == 1 e nuova modalità == `0x2C`, **ripristina guard = 7** (0xCA4BE).

Correzione all'iterazione 39: «nessuno scrittore statico di `0xC8E80C`» è falso — `0xCA4AE` è uno scrittore statico via pool `0xCA5D0`, sfuggito al censimento precedente (che aveva classificato i lettori inline `0xCA418`, `0xCA726`, `0xD04C0` ma non lo store). La rilettura interpretativa segue in §5.

### 4. Cella flag 0x36580C: lettori e scrittori completi

Scan LE su tutti i 16 payload: `0x36580C` compare in **un solo** pool (payload 0, `0xCA18C`); `0x365751` in un solo pool (`0xCA30C`); `0x365750` in 14 pool del payload 0. Utenti del pool `0xCA18C`: la lettura di restore `0xCA4AA` e il teardown `0xC9DF0` (in `0xC9DB6`: guard=0 via setter a 0xC9DEA, poi `stb_s r15,[r0,0]` con r15=0 → flag=0). Le finestre limitate (48 byte) dei 24 siti utente dei 14 pool di `0x365750` non contengono **nessuno** store a offset 188 tranne la coppia di salvataggio 0xCA496/0xCA49E: la semantica «flag = la guardia valeva 7 in 0x2C» non ha altri produttori statici. **Post-audit**: la guardia stessa invece ha anche i due scrittori diretti della funzione switch `0xCBC00` (store `[r2,1]` a 0xCBC24/0xCBC2A, valori solo 0/4; vedi §Revisione) — il setter `0xCA2F4` non è l'unico canale di scrittura della guardia, resta però l'unico che può scrivere 7.

### 5. La regola EA di ld.as a PC 2 mod 4 (prova CPU)

Il restore legge il flag con `ld.as r0,[pcl,-199]` a 0xCA4AA (PC 2 mod 4; byte in memoria `39 17 00 f6`, forma visiva GNU `1739 f600`, commento objdump `;0xca3e1`). Due casi CPU su simulatore GNU ARC700 (bancarella ELF dedicata 0xC00..0x1000, stesso encoding byte-identico al firmware):

- caso A: marker al valore alla EA scalata `(PC&~3)+imm*4 = 0x1000-796 = 0xCE4` → carica il marker, fault di lettura voluto a `0xdead0000` (pc 0x1026): **l'EA effettiva è (PC&~3)+imm*4**, quindi il pool letto è `0xCA4A8-796 = 0xCA18C` = 0x36580C;
- caso B (controllo negativo): marker solo all'indirizzo non scalato `0xF39` → il marker non viene caricato, fault a `0xdead0004` (pc 0x101a): l'EA non scalata mostrata da objdump **non** è quella usata dall'hardware.

Entrambi i casi: exit 11 (fault atteso), 5 istruzioni, fault address/pc conformi all'oracolo. Il commento visivo `;0xca3e1` di objdump per PC 2 mod 4 è quindi fuorviante e non va usato come EA.

### 6. Riconciliazione con il record TBIB 8

`0xC8E80C` è il byte a `+0xC` del record TBIB 8 (base `0xC8E800`, magic `C1C2C3C4` a `+0x4` — a `+0` c'è `0x5FA3` —, payload 8, «NotRunOneCard» nell'iterazione 27): valore statico nel dump `0x2C` verificato qui byte per byte. Gli altri 7 pool che contengono `0xC8E80C` sono classificati a finestra: `0xC9C98` scrive `+1`, `0xCB4C0` legge/scrive `+3`, `0xCE390` scrive `+7`, `0xD04BE` legge il byte in una copia di struct, `0xD0A1A` scrive l'array word `0xC8EB30+` (`[r2,201..209]`), `0xD0FF4` legge `[r2,215..217]`, `0xCA726` legge il byte: nessun altro tocca `+0xC`. L'iterazione 39 concludeva «selettore di variante boot, non modalità runtime»: la transizione `0xCA404` (63 chiamanti bl) con change-detection, salvataggio/ripristino della guardia e i casi speciali `0x38`/`0x6C`/`0x6E`/`0x5`/`0x7D`/`3`/`0x2C` mostra invece che la cella è **usata a runtime come modalità di scatto corrente**, inizializzata dal valore del record TBIB (0x2C nel dump). Il significato fisico dei singoli valori resta aperto; l'aggiornamento dell'interpretazione va in mappa RAM via PMB, non nel diario compattato.

## Revisione indipendente (agente `guard-audit-42`)

Audit eseguito in questa sessione con metodo indipendente (byte grezzi dai 16 blocchi TBM con SHA verificati, objdump GNU fresco, censimenti `$`-anchored ripetuti su ridisassemblato indipendente, scan LE propri a ogni allineamento, censimento «pool+aritmetica» su tutto il listing). C1–C7 CONFERMATI byte-exact. C8 (controesempi): **un controesempio reale, integrato sotto**; le conclusioni chiave restano valide. Gli agenti `guard-audit-40`/`guard-audit-41`, avviati nelle sessioni interrotte, non hanno mai risposto (sessioni terminate in attesa; documentato nel checkpoint).

**Controesempio — la guardia ha due scrittori diretti oltre al setter.** Funzione switch con ingresso `0xCBC00` (`push_s blink`, tabella a `0xCBC1C`, `r0 ∈ 0..4` con `bhi` a uscita): carica la base dal pool `0xCBC38 = 0x365750` (a 0xCBC14) e scrive `stb_s r1,[r2,1]` a **0xCBC24/0xCBC2A** — cioè direttamente il byte guardia `0x365751`, senza passare dal setter `0xCA2F4`. La jump table usa `add1` (secondo operando scalato ×2): le voci `[03,03,03,06,03]` portano `r0 ∈ {0,1,2,4}` a 0xCBC22 (`mov_s r1,0` → scrive **0**) e `r0 = 3` a 0xCBC28 (`mov_s r1,4` → scrive **4**); `r0 > 4` esce senza scrivere. **Mai 7**: la conclusione «unico produttore statico di guard=7 = restore 0xCA4BE» è quindi confermata e rafforzata (il censimento `mov r0,7` + `bl` su tutti i 27 siti trova solo 0xCA4BE; nessun limm/puntatore statico verso i quattro target; nessun puntatore-funzione ai target nel dump). Verificato in coordinatore byte per byte (finestra allineata 0xCBC00..0xCBC30, byte grezzi della tabella, target con semantica `add1`) e con censimento indipendente: gli unici store `[rN,1]` entro 12 righe dal load di uno dei 14 pool di `0x365750` sono proprio 0xCBC24/0xCBC2A. Nota: l'agente aveva scambiato la mappa r0→valore (r0=2→4); la mappa corretta è r0∈{0,1,2,4}→0, r0=3→4. La reachability di 0xCBC00 è indeterminata (nessun `bl`/`j` statico individuato). Il valore 4 scritto qui è lo stesso stato guard==4 condizionato dai due siti const3 di §2 — il produttore del contesto «guard=4» è ora candidato (funzione 0xCBC00, chiamanti ignoti).

**Correzioni di dettaglio accolte e riverificate:**

- **Magic TBIB record 8 a `+0x4`, non a +0**: byte grezzi `a3 5f 00 00 c4 c3 c2 c1 … 2c` — a `+0` c'è `0x5FA3`, il magic `C1C2C3C4` è a `+0x4` e il byte modalità a `+0xC` vale `0x2C` (confermato).
- **Liveness di r13 (§3.1)**: il censimento «nessuno scrittore fra 0xCA416 e 0xCA4AE» è a finestra; non esclude clobber da parte dei callee intermedi (`0xCADAA8`, `0xCA5DC`, `0xCA6FC` non auditati per r13; ABI ARC: r13 callee-saved).
- **Listing lineare**: le istruzioni dentro le regioni `.long` dei pool non compaiono nel listing (es. il `ld` del getter 0xCA310); i censimenti `$`-anchored restano validi per i `bl`, ma le finestre allineate restano lo strumento corretto.
- **Docstring del verificatore**: «constant 0 (16 sites)» è impreciso — le classi congelate const0* sono 14; le asserzioni interne impongono i conteggi corretti, quindi è solo imprecisione di commento (non corretta nel file per non invalidare gli hash delle evidenze congelate).
- Censimenti del flusso 0xCA404: l'agente conferma anche la ripartizione per payload dei 63 bl della transizione (15/10/38) e dei 434 del getter modalità (85/291/58), assente nel rapporto originale.

## Riproduzione e limiti

Esecuzioni del verificatore, tutte PASS con classificazione dei 27 siti e oracoli dei casi byte-identica (differiscono solo i campi `utc` e gli hash dei `.command.json`, che contengono i percorsi auto-referenziali delle directory di prove):

- sessione interrotta 1 (round terminato durante le regressioni): `PASS_CAPTURE_GUARD_SETTER_CENSUS 20261101T111303504606Z` (dopo le bozze 1102..1105Z, riferimento `20261101T110537213758Z`);
- sessione interrotta 2 (round terminato durante le regressioni): `20261101T112121924544Z`;
- chiusura in questa sessione: `20261101T112305687536Z` (confronto ricorsivo completo contro la 110537Z: unici delta `utc` e hash dei file di comando/log).

Regressioni rieseguite in questa sessione senza pipe, tutte PASS: `s33_verify_capture_flag_mode_matrix_cpu.py` (14 casi, `20261101T112306442802Z`), `s33_verify_snapshot_capture_record_init_cpu.py` (4 casi, `20261101T112307559937Z`), `s33_verify_service_raise_pending.py` (statico it. 38, `20261101T112308Z`). Nelle sessioni interrotte erano già PASS: flag matrix `20261101T111324680216Z`, snapshot `20261101T111330450836Z`, raise pending `20261101T112141Z` (le altre due regressioni del round interrotto 2 non hanno prodotto evidenze su disco e sono state rieseguite qui).

Assunzioni: le classificazioni dei siti sono statiche (finestre congelate); i due casi CPU usano RAM/pool sintetici con lo stesso encoding del firmware, non il firmware in banco; il censimento `bl` copre le forme `bl|bl.d|bl_s|bl_s.d` del listing lineare e non i salti indiretti; le finestre di esclusione (+188 e +1) sono a raggio limitato, non data-flow completi.

Limiti: i 9 argomenti calcolati del setter non sono circoscritti a un insieme di valori (il produttore «runtime» di guard=7 via siti calcolati non è escluso); i due scrittori diretti della switch 0xCBC00 non scrivono mai 7 ma la loro reachability è indeterminata; liveness di r13 a finestra (clobber da callee non escluso); nessuna esecuzione del percorso 0xCA404 con stato reale (scheduler, WindowManager, eventi); nessuna prova su hardware, tasti fisici, rendering o scatto; V1.1 campione vs macchina V1.0. **NON_INSTALLARE**; progresso funzionale ~10% invariato.

## Prossimo passo

Chi sono i 63 chiamanti di `0xCA404` e quali valori di modalità passano (in particolare chi porta a/da `0x2C`): è il pe mancante per chiudere il ciclo guardia — «snapshot → coda → dispatcher → AutoScene/manager → CaptureMenu → transizione 0xCA404 → guardia/flag → flag bit 1 liste». In parallelo: la reachability della switch `0xCBC00` (chi la chiama con r0∈0..4; produce guard 0/4 e nessun chiamante statico è noto) e il significato del contesto guard==4. Alternativa già indicata: walker delle tabelle di classe alta del servizio (it. 38).
