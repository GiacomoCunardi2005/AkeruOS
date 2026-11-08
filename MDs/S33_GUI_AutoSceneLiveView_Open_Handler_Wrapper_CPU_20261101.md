# AutoSceneLiveView: handler di apertura 0x4401 (0x659554) e wrapper eventi 0x6593A0 — statica + 19 casi CPU su byte originali

**Iterazione 28 — 1° novembre 2026.** Chiude il punto aperto di it.25
(checkpoint 2026-11-01): «handler 0x4401 di apertura della finestra
0x659554 …; oppure il secondo registro p6 0xAF5F08 che riusa 0x659554».

## Domanda affrontata

Che cosa fa l'handler di apertura 0x659554 (evento 0x4401, registro
finestra p3 0x783B08) e — ancor più importante — con quale gate il
wrapper della finestra 0x6593A0 decide quali pressioni pulsante
raggiungono gli handler slot 0x65C46C/0x65C6B4 decodificati in it.25.
Conseguentemente: 0xAF5F08 (p6) è davvero un «secondo registro notifiche»?

## Risultato verificabile e significato

**PASS_ASLV_OPEN_WRAPPER** (verificatore nuovo
[Python_Trace_Scripts/s33_verify_aslv_open_wrapper_cpu.py](../Python_Trace_Scripts/s33_verify_aslv_open_wrapper_cpu.py),
19 casi CPU su byte originali, due run identiche). Risultati principali:

1. **Handler di apertura 0x659554** (payload 2, pool 0x659594=0x681F5C e
   0x659598=0x47BBC8; unica chiamata via registro p3, 0 bl caller):
   prologo push_s blink + bl millicode 0x33412C, salva (node, ev, arg),
   chiama 0x65D6A0, poi
   `[0x681F5C+8] := 0xFF`, `[0x47BBC8] := 0`, legge la guardia
   CaptureMenu con il getter ORIGINALE 0xCA310 (byte 0x365751) e la
   copia in `[0x681F5C+9]`, la riscrive con il setter ORIGINALE
   0xCA2F4 (che ignora r1 residuo e riscrive lo STESSO valore), salva
   l'argomento in `[0x681F5C+0x18]` (word) e ritorna r0 = 0x681F5C.
   **Non tocca la cella stato [ctx+4]**.

2. **0x65D6A0** (unico caller: 0x659568): `[0x681FBC] := node` (word;
   0x681FBC = ctx+0x60), chiama 0x65C920 — due istruzioni originali
   (`j_s.d [blink]` + delay slot `ld_s r0,[pcl,+4]`, pool
   0x65C924=0x47BBB8) — che **restituisce il PUNTATORE 0x47BBB8, non
   il byte**: il puntatore viene salvato in `[0x681FBC+8]` e passato
   come r0 a 0x189D78 (servizio, stub).

3. **Wrapper 0x6593A0** (descrittore 0x783AE8, 0 bl caller): è il vero
   **gate degli eventi finestra**, PRIMA della dispatch sul registro
   p3. Calcola `r14 = (ev & 0x3F80) >> 7` (slot di range) e filtra in
   base alla **cella stato [0x681F5C+4], letta come WORD 32 bit**:
   - eventi fuori [0x80..0x307F] (lifecycle 0x4401/0x4405, ecc.):
     diretti al router 0x169F60(ctx, 0x783B08, node, ev, arg);
   - stato 6 + slot {1,2,3,0x10,0xC}: blocco speciale 0x6593FC
     (r18 = ev&1; slot 1 chiama 0x65D2E8 sia su pressione che su
     rilascio; il rilascio esce subito al router);
   - **stato 6 con qualsiasi altro r14 → ritorno 0 SENZA dispatch**:
     i quattro slot pulsante (0x580/0x700/0x2180/0x2700 →
     r14 = 0xB/0xE/0x43/0x4E) sono inghiottiti;
   - stato 2: gate `cfg[1]` (lettura ORIGINALE 0x16F920, byte a
     0x446808 + 4·id via `add2_s`): `cfg[1]==0` → prosegue al gate
     guardia; `cfg[1]!=0` → ritorno 0 **solo per
     r14 ∈ {0x11,0x12,7,8,9,0xA,0xB,0xC,0xE,0xF,0x43,0x4E}**
     (catena 0x659432..0x659460; i quattro slot pulsante sono tutti
     nel set), con altri r14 il flusso prosegue al gate cfg[8]
     (correzione della revisione indipendente: il gate non è
     incondizionato);
   - guardia 7 + 0xD10C4()==1 + stato {2,3} + `0 < byte[ctx+0x23] ≤ 6`
     + r14 {3, 0xC} → ritorno 0;
   - `cfg[8] != 0` → sotto-gate pulizia; `cfg[8]==0`: `cfg[7]==0` →
     router, altrimenti sotto-gate pulizia;
   - **stato {4,5}**: r14 {9,0xA,3,0xB,0xE,0x43,0x4E,0xF} →
     ritorno 0 (**i quattro slot pulsante sono inghiottiti anche negli
     stati 4 e 5**); r14 {1,2} → sotto-gate zoom (contatore 0x14A1F8
     contro soglie 100/400, cfg[8], 0x1493D8/0x14941C — con
     `0x14941C()==1` uscita DIRETTA al router a 0x6594F8 —, cfg[7],
     e re-lettura di [ctx+4] a 0x659510: stati 4/5 → ritorno 0,
     altri → router);
     ogni altro r14 → 0x65951C: **`[ctx+4] := 0` (word), bl 0x1493BC,
     `bl.d 0x145C3C` con delay slot `r0 = 0x30D40` (pool 0x65954C),
     POI router** — il wrapper stesso può azzerare lo stato finestra
     e il delay slot è eseguito CORRETTAMENTE dal sim (prima prova di
     un bl.d con delay-slot LIMM nel banco);
   - ogni altro stato → router; il risultato del router è restituito
     in r0.
   Consequenza per AkeruOS: la visibilità degli handler slot it.25
   dipende da [ctx+4] e dalle celle cfg[1]/[7]/[8]: la coda AkeruOS non
   può assumere che una pressione in arrivo produca sempre una
   notifica CaptureMenu (2,4)/(2,5).

4. **p6 0xAF5F08 non è un secondo registro notifiche** (chiude il
   dubbio it.25): è un record della tabella di COPPIE di indirizzi
   0xAF4B70..0xAF5F68 (639 record {u32, u32}, tutti puntanti nel
   codice del blocco 2, 0x5FE800..0x669800); il record @0xAF5F08 è
   (0x659554, 0x659555) — un intervallo di codice, non un accoppiamento
   evento→handler.

5. Registro p3 0x783B08 ricontrollato (39 record + terminatore
   {0, 0x20E814}@0x783C40): 0x4401→0x659554, 0x4405→0x65959C,
   0x4406→0x659EF0, 0x4409→0x65A4A4, 0x440E→0x659FA0,
   0x400C→0x65A708, 0x7D40→0x65AB5C.

6. Census bl su 16 listati GNU: 0x659554 = 0, 0x6593A0 = 0 (callback
   puri), 0x65D6A0 = 1, 0x65C920 = 1, 0x65D2E8 = 3. LE scan: 0x659554
   solo a 0x783B0C (campo handler del record 0x4401) e 0xAF5F08;
   0x6593A0 solo a 0x783AF4 (descrittore); 0x47BBC8 solo ai pool
   0x659598/0x65A3B0/0x65C400 (scritta a 0 anche dall'handler 0x4406 e
   da quello 0x180).

7. 0x65D2E8 (stub nel banco, decodifica statica completa post-revisione):
   **15** chiamate `jl_s` a 0x17BF60(0, id, id) via pool
   0x65D384 = 0x17BF60 per gli id 0x180, 0x380, 0x400, 0x480,
   0x500, 0x580/0x581, 0x600/0x601, 0x700/0x701, 0x2180/0x2181
   (pool 0x65D388), 0x2700/0x2701 (pool 0x65D38C) — purga della coda
   dei QUATTRO SLOT PULSANTE (pressione+rilascio) oltre agli ID della
   lista di esclusione p5 0x99ACAC; coda `b 0x65CECA`; ignora i
   propri argomenti di ingresso (riceve r0 = ev&1 dal bmsk del
   wrapper).

## Fonti, indirizzi e file

- Blocchi 0/2/3 del firmware V1.1 (payload verificati
  `s33_trace_state_dispatch.verified_payloads`).
- Finestre CPU byte-originali: `.mili` 0x334100..0x3341E4 (push
  0x334114/11C/124/12C/130 + pop 0x334174/17C/184/18C/194/19C/1A4),
  `.guard` 0xCA2F4..0xCA31A (setter+getter+pool 0xCA30C=0x365751),
  `.cfgread` 0x16F920..0x16F928 + pool 0x16FA34=0x446808, `.wrap`
  0x6593A0..0x659554, `.open` 0x659554..0x65959C, `.d6a0`
  0x65D6A0..0x65D6D0, `.c920` 0x65C920..0x65C928.
- [Evidenze run 1](../Risultati/GUI_S33/aslv_open_wrapper_cpu_20261101T170345784381Z/),
  [riesecuzione identica](../Risultati/GUI_S33/aslv_open_wrapper_cpu_20261101T170413338706Z/)
  (evidenze byte-identiche salvo `utc`; 19/19 casi, fault
  0xDEADB001..0xDEADB013).

## Comandi realmente eseguiti ed esiti

- `python3 Python_Trace_Scripts/s33_verify_aslv_open_wrapper_cpu.py` →
  **PASS_ASLV_OPEN_WRAPPER 20261101T170345784381Z** + riesecuzione
  identica **170413338706Z** (confronto JSON: identico salvo utc).
- Regressioni 6/6 PASS: snapshot record init **170439048305Z**, guard
  setter census **170439820601Z**, service raise pending **170451Z**,
  wm notify registry **170455525917Z**, notify reactors
  **170458416927Z**, aslv slot handlers **170504924640Z**.
- Analisi statica: objdump GNU ARC700 su finestre carve dai payload,
  LE scan `le_scan`, census listati GNU (16 blocchi), tabella p6
  scandita record per record.

## Fixture e assunzioni

- Contesto 0x681F5C (0x68 byte, sentinelle 0xA5): **[ctx+4] impostato
  come WORD 32 bit** (scoperta al primo fallimento: `ld_s r0,[r13,0x4]`
  legge 4 byte, non 1); byte [ctx+0x23] per caso.
- Guardia 0x365751 fixture (getter/setter ORIGINALI eseguiti), tabella
  cfg 0x446808 fixture (byte id 1/7/8; lettura ORIGINALE 0x16F920),
  celle 0x47BBB8/0x47BBC8 fixture con sentinelle.
- Stub con logger {id, r0, r1, r2} a 0x367100+16k, contatore 0x367000,
  specchietti r3/r4 del router a 0x367310/14, cella valore di ritorno
  0x367320; stub a 0x169F60/0x65D2E8/0x145C3C/0x1493BC/0x1493D8/
  0x14941C/0x14A1F8/0xD10C4/0x189D78; ritorni imposti per caso.
- Assunzione: il significato runtime degli stati [ctx+4] {0,2,3,4,5,6}
  e di cfg[1]/[7]/[8] NON è dedotto (RAM runtime, produttori aperti).

## Controlli negativi e regressioni

- Inghiottimento: stati 6/5/4 con i quattro slot pulsante → ritorno 0,
  ZERO chiamate stub, cella stato invariata (casi 3/4/5/11/14).
- Gate cfg[1]=1 → inghiottito (caso 9); cfg[1]=0 → prosegue (10).
- Percorso pulizia stato 5/slot sconosciuto: [ctx+4] azzerato +
  0x145C3C riceve esattamente 0x30D40 via delay slot (13).
- Guardia 7 ripristinata identica dal setter nell'handler (17/18/19),
  vicini 0xA5 intatti; [0x47BBB8] (byte) non letto dall'handler;
  0x65C920 restituisce il puntatore, non il valore.
- Rilascio slot 1 in stato 6: 0x65D2E8 + router senza gate successivi
  (8) — polarità confermata dal caso CPU, non solo dalla statica.
- Assert «nessuna chiamata oltre il conteggio atteso» in ogni caso.

## Lezioni di banco (nuove)

1. `ld_s rX,[r13,off]` carica SEMPRE una WORD 32 bit: una fixture
   a byte su una cella letta con ld_s produce confronti word su
   0xA5A5A5xx e fallimenti fuorvianti (accaduto su [ctx+4]).
2. Il `bl.d` firmware con delay slot che carica un LIMM nel registro
   argomento (0x659524/28) è eseguito CORRETTAMENTE dal sim: la
   chiamata riceve il valore del delay slot (0x30D40).
3. Alla call-site il valore r0/r1/r2 residuo è il risultato
   dell'ULTIMA istruzione prima del bl (es. 0x65D2E8 riceve r0=ev&1
   dal bmsk; 0x189D78 riceve r0=0x47BBB8): asserire sempre il
   produttore immediato, non «il nodo» per abitudine.
4. Una funzione di due istruzioni con `j_s.d` restituisce il valore
   del delay slot: 0x65C920 è un «return &cella», non un getter.

## Revisione indipendente (agente `openwrap-review-28`)

Revisione ex-novo (carve propri + objdump GNU, census LE propri su 16
blocchi, 152/152 finestre congelate byte-identiche al payload, due run
congelate confrontate): **C1/C2/C4/C5/C6/C8 CONFERMATI CON
PRECISIONE**; C3 confermato con la correzione del gate (c) sopra; C7
conteggio corretto 8 → 15 (integrazione sopra). Controesempi accolti
e integrati: gate (c) non incondizionato; uscita 0x6594F8 del
sotto-gate zoom; re-check di [ctx+4] a 0x659510; stato 6 con
r14 ∈ {2,3,0x10,0xC} pressione NON inghiottito (prosegue ai gate —
coerente con la lettura (a)/(b) del presente rapporto); nessuno store
non dichiarato; tutte le polarità di branch conformi. Census
0x65D2E8: 3 caller = 0x65940A, 0x659418 (wrapper) + 0x65B04E.

**Writer statici di [ctx+4] (0x681F60) — census della revisione**
(13 store in 9 funzioni, tutti blocco 2; lettori diretti via pool
0x681F60: 0x65BC06, 0x65C038, 0x65CDC2, 0x65D030, 0x65D05A):

| Store | Funzione (evento registro p3) | Valore/condizione |
|---|---|---|
| 0x65951E | wrapper 0x6593A0 | :=0 (percorso «altro r14», stati 4/5) |
| 0x65964A | handler 0x4405 (0x65959C) | :=0 (teardown della struct) |
| 0x6599C2 | handler 0x4405 | :=2 |
| 0x65A9F6 | handler 0x400C (0x65A708) | :=0 se stato==5 ∧ 0x149474()!=0 |
| 0x65AD32 | handler 0x7D40 (0x65AB5C) | :=r15 se stato==8 |
| 0x65B0DA | handler 0x81 (0x65B060) | :=0 |
| 0x65B212 / 0x65B2EA | handler 0x100 (0x65B1CC) | :=2 (byte[0x47BBC8]>0) / :=6 |
| 0x65B3E8 / 0x65B562 / 0x65B594 | handler 0x380/0x400 (0x65B3A8) | :=0 se stato==8 / :=4 / :=5 |
| 0x65B6AA | handler 0x381/0x401 (0x65B5D4) | :=0 |
| 0x65D0D6 | helper 0x65D098 (da 0x65B1CC) | :=2 se stato==6 ∧ guardia 0xCA310==1 |

Valori di stato osservati staticamente: 0, 2, 4, 5, 6 (+r15
condizionali). Writer dinamici via contesto passato in registro non
coperti dal census statico.

## Limiti e questioni non dimostrate

- Statica + 19 casi CPU con fixture: nessun hardware, boot,
  rendering, scatto, persistenza; NON_INSTALLARE; ~10% invariato.
- Produttori RUNTIME di cfg[1]/[7]/[8] e dei valori 0x47BBB8/
  0x47BBC8: APERTI. I writer STATICI di [ctx+4] sono censiti
  (13 store in 9 funzioni, tabella della revisione) ma NON provati in
  CPU; writer dinamici via contesto in registro restano possibili.
- 0x169F60, 0x145C3C, 0x1493BC/D8/41C, 0x14A1F8, 0xD10C4, 0x189D78,
  0x65D2E8 sono STUB (semantica solo statica); il router non è stato
  rieseguito in catena con 0x65C46C.
- Significato funzionale degli stati {2,3,4,5,6} e della cella
  [ctx+0x23] non identificato; unità del contatore zoom 0x14A1F8
  ignote.
- V1.1 vs V1.0 non confrontato per queste finestre.

## Prossimo passo concreto

Il census statico dei writer di [ctx+4] è ora fatto (tabella sopra,
revisione): il prossimo passo è **decodificare e provare in CPU
l'handler 0x4405 (0x65959C, chiusura)**, che è il writer più ricco
(0 e 2) e il naturale consumatore del contesto predisposto
dall'handler di apertura 0x659554, per chiudere il ciclo
apertura→stato→chiusura della finestra; in alternativa i writer
0x65B212/0x65B2EA (handler 0x100: stati 2/6 legati a
[0x47BBC8]) oppure il ramo 0x63 di 0x20F414 e il callback 0x7F6824.
