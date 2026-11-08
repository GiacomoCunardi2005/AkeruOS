# Iris — scrittori della coppia di stato 64-bit: setter 0x16E3A2, commit 0x16EC38 e catena di registrazione (iterazione 31)

Verificatore: `Python_Trace_Scripts/s33_verify_iris_state_pair_writers.py`
Prove: `Risultati/Lens_MCU_Interface/Iris_State_Pair/latest.json`
(**evidenza valida 20261022T022435Z post-audit**; la 20261022T021333Z
della stessa sessione è la corsa pre-audit; nessuna asserzione
indebolita: le correzioni dell'audit sono state accolte nel modello
con asserzioni più forti).
Campione: firmware V1.1, SHA-256
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`,
payload0 Main base 0x0AD800, blocchi sha-verificati del manifest.

## 1. Domanda

Chiude il punto (b) dell'iterazione 27 / prossimo passo (a) dell'iterazione
29: **chi scrive a runtime la coppia di stato a 64 bit** della macchina a
stati dietro la shadow diagnostica 0x446808 — la coppia `+0xC/+0x10` della
struct 0x3678E4 consumata da 0x16F86C — da cui nascono i bit **16/21/15**
che il pannello iris 0x2C5074 legge come richieste 8/9/0xA.

## 2. Risposta sintetica

La coppia ha esattamente **tre scrittori statici**, tutti verificati
byte-exact in payload0:

| Scrittore | Firma | Semantica | Come è raggiunto |
|---|---|---|---|
| **0x16E3A2** | (secondary, value) | setter generico di un bit: tabella record 0x392F04, posizione `rec[+8]` | **NESSUN chiamante statico** (negativo onesto, vedi §7) |
| **0x16EC38** | (newLo, newHi) | commit di coppia dopo normalizzazione/validazione 0x16E6E0 | function pointer in cella **[0x366DE8]**, invocato da **0x1406D0(x) = [0x366DE8](~x, 0)** |
| **0x16F8EC** | (pair) | complementare: committa `~pair` e forza tutti i record | solo init, chiamante 0x16E336 nell'installer 0x16E2F4 |

Censimento (listato lineare, forme bl/bl.d/bl_s/bl_s.d, riverificato in
finestra dedicata per i siti della catena): chiamanti di 0x16F86C =
{0x16E3FA, 0x16EC74, 0x16F90A}; 0x16F90A è dentro il corpo di 0x16F8EC.

## 3. Il setter 0x16E3A2(secondary, value)

Ingresso 0x16E3A2: `bl 0x334120` (salvataggio millicode r13-r18, nessun
`push_s blink`: il ritorno passa per `b 0x33417C`), frame, `r18=r0`
(secondary), `r17=r1` (value). Loop `r14 = 0..0x10`:

- `ld r12,[pcl,-52]` → pool **0x16E388 = 0x392F04** (tabella record,
  base non scalata (PC&~3)+campo);
- `asl_s r13,r14,0x2` + `add2_s r13,r13,r13` = ×5 → **stride 20**;
- `ldb_s r1,[r13,0x9]` (rec.idx) `cmp r1,r18`: match sul secondary;
- `mov r0,-1; mov_s r1,r0; bl 0x16F914` = **lettura coppia con maschera
  piena** (0xFFFFFFFF/0xFFFFFFFF);
- `ld_s r2,[r13,0x4]` (maskHi), `ld_s r3,[r13,0]` (maskLo),
  `bic r16,r1,r2` / `bic r15,r0,r3` (pulizia dei bit del record);
- `ldb_s r2,[r13,0x8]` = **posizione di bit** (correzione confermata
  dell'audit 27: il campo +8 è la posizione, non il valore);
- `mov_s r0,r17; mov_s r1,0; bl 0x334E9C` = **`__ashldi3`**: 64-bit
  `value << bitpos`;
- `or_s r15,r15,r0` / `or r1,r1,r16` → nuova coppia;
- `mov_s r2,0x1; bl 0x16F86C(newLo,newHi,1)` a **0x16E3FA**.

**Negativo strutturale**: zero `bl/b/jl` con target 0x16e3a2 nel
listato, zero word LE 0x16E3A2 e zero limm middle-endian nei 16
payload, zero jump table (ldb.x/add1_s) che lo raggiunga (verificate le
due tabelle della famiglia: 0x16E46C classificatore e 0x16F45C switch
parametri ctxB). Il setter è raggiungibile solo per dispatch calcolato
(cieco al censimento lineare) oppure è codice morto in V1.1.

> **Correzione 29 ottobre 2026:** il limite di un bit descritto sotto vale per ciascun gruppo separatamente, non per l'insieme dei bit campionati. Le affermazioni sui rifiuti di 16+21 e 15+20 e il modello Python storico sono errati su coppie appartenenti a gruppi differenti. [Analisi corretta e prova CPU](S33_GUI_Normalizzatore_Gruppi_Correzione_CPU_20261029.md).

## 4. Il commit 0x16EC38 e il normalizzatore 0x16E6E0

**0x16EC38(lo, hi)**: copia gli argomenti nella coppia locale
[fp-8]/[fp-4], `sub r0,fp,0x8`, `bl_s 0x16E6E0(&pair)` a 0x16EC64; se
ritorna 1 → `bl 0x16F86C(pair, flag=1)` a 0x16EC74.

**0x16E6E0(&pair)** (struct **0x367898**, pool 0x16E834 — distinta dalla
struct consumatore 0x3678E4):

- gate byte `[0x367898+0xA]` (0x3678A2), mirror halfword
  `[0x367898+4]` (0x36789C);
- se gate == 1: azzera il gate e **forza bit0 = 1** di lo; se gate != 1:
  bit0 cancellato dalla maschera;
- **lo' = lo & 0xFE31B188** (pool 0x16E830; complemento
  **0x01CE4E77**, bit cancellati
  {0,1,2,4,5,6,9,10,11,14,17,18,19,22,23,24});
- campiona la coppia via **0x335C4C = `__lshrdi3`** con shift 5, 10, 15,
  20 e maschere 0xC/0xC/**3/3** (`bmsk_s ,0x1` maschera DUE bit,
  correzione dell'audit 31) → bit campionati
  **{7, 8, 12, 13, 15, 16, 20, 21}** di lo; il byte con `lo'&8`
  ([fp-20]) è calcolato ma non contato dal loop 4×5 (che legge solo
  [fp-24..fp-21]);
- **bypass magico**: `(lo',hi) == (0xFE003000, 0)` accettato senza
  contare;
- altrimenti loop 4 byte × 5 bit: **al più un bit campionato**, se due →
  ritorna 0 SENZA scrivere la coppia;
- accettazione: `*(&pair) = (lo',hi')`, mirror = bit0(lo'), ritorno 1.
  Il **ramo gate==1 salta** sia il magic sia la validazione
  (`b_s` → 0x16E810).

## 5. Catena di registrazione e invocazione runtime

L'**installer 0x16E2F4** (chiamato da 0xC5D9E) oltre a installare la
tabella record (0x16F66C(0x392F04, 16)) e registrare l'handler 0x16E588,
fa l'init e le registrazioni:

1. `bl 0x14066C` (getter condiviso: `bl 0x22C434` + `not r0`) → coppia
   iniziale (~X, 0); `0x16E6E0(&pair)`; `bl 0x16F8EC(pair)` a 0x16E336 =
   **commit complementare di boot** (tutti i record con maschera non
   nulla sparano);
2. `bl.d 0x140634` con r0 = pool **0x16E390 = 0x16EC38** →
   **[0x366DE8] = 0x16EC38**;
3. `0x1405F8(4, pool 0x16E394 = 0x16ECB4)` → **[0x366DE0]** (cella
   id-4); `0x1405F8(2, pool 0x16E398 = 0x16EC88)` → **[0x366DE4]**
   (cella id-2). NB (correzione audit 31): in 0x1405F8 il case r0==4
   carica il pool 0x14062C (=0x366DE0) e il case r0==2 il pool
   0x140630 (=0x366DE4): le celle si etichettano con l'id che le
   SCRIVE (la prima stesura di questo rapporto aveva id-2/id-4
   invertiti);
4. `bl.d 0x148F64` con r0 = pool 0x16E39C = 0x16EE7C → **[0x366F78]**.

Il **setup 0x140568** (chiamato da **0xC5D88**, stessa funzione padre di
0xC5D9E: boot-time, un solo punto) registra gli invocatori:

- `0x22C3BC(0x1406D0, 0, 0, arg, 0x14)`: memorizza il puntatore a
  `[0x5545F8+0x18]` (struct, pool 0x22C474) **solo se la cella è
  vuota**, e con r1 != 0 (nella chiamata del setup r1 diventa 1) fa
  **event SET 0x158CBC(0x3200002, 1<<10)**;
- `0x16ACDC(7, 2, 0x140704)`: halfword **7** a +0x14 (`bmsk_s ,0x2` =
  &7; 7&7=7 — correzione audit 31, la prima stesura diceva 3), 2 a
  +0x16, puntatore a **[0x392AC0+0x1C]** (pool 0x16ADC0);
- `0x16C6AC(0x140700, ·)` con 0x140700 = tail verso 0x1406BC (legge il
  byte [0x366DF0], se != 0 → 0x16C70C).

Gli invocatori:

- **0x1406D0(x)**: r2 = [0x366DE8] (pool 0x14064C); se != 0:
  `not_s r13,r14`, r0 = **~x**, r1 = **0**, `jl_s [r2]` →
  **0x16EC38(~x, 0)** = commit del complemento dell'argomento;
- **0x140704(bits)**: bit2 → [0x366DE0] = **0x16ECB4** (id-4); bit1 →
  [0x366DE4] = **0x16EC88** (id-2); bit0 → [0x366DDC] (id-1; la
  `ld.as r0,[pcl,-69]` a 0x14073E ha pool = (0x14073C)+(-69×4) =
  **0x140628**; nessuna cella id-1 è registrata nei 16 payload: ramo
  di fatto inerte salvo writer runtime).

NB toolchain riconfermato: `ld`/`ld_s` non scalati ((PC&~3)+campo,
es. 0x16E3BE→0x16E388), `ld.as` scalato ×4 ((PC&~3)+campo×4,
es. 0x14073E→0x140628, oltre alla calibrazione storica 0xCAD30→0xCAAC4).

## 6. Conseguenza per le richieste iris 8/9/0xA

La maschera 0xFE31B188 **non cancella nessuno dei bit di record** (i bit
cancellati 0x01CE4E77 = {0,1,2,4,5,6,9,10,11,14,17,18,19,22,23,24} sono
disgiunti dai bit di stato {3,7,8,12,13,15,16,20,21,30,31} + bit alti):
la normalizzazione preserva esattamente i bit definiti dalla tabella
record. Quindi:

- i bit **16/21** (richieste 8/9 Big) e **15** (richiesta 0xA Small)
  possono nascere dal **setter 0x16E3A2** (secondary 8/9/0xA),
- dal **commit 0x16EC38/0x1406D0**: anche i bit 16/21/15 però sono
  **campionati** dalla validazione «al più un bit»
  (set {7,8,12,13,15,16,20,21}, correzione audit 31) → dal percorso
  commit ogni singola richiesta può nascere, ma una commit con **due
  richieste simultanee** (es. bit16+bit21 o bit15+bit16) è RIFIUTATA
  senza scritture,
- o dal **commit complementare di init 0x16F8EC** (tutti i bit accesi
  all'avvio; ramo gate==1 che salta la validazione).

Il setter NON passa dal normalizzatore e non è vincolato dalla
validazione. L'origine runtime delle richieste non passa quindi per
uno scrittore esterno alla famiglia: è chiusa staticamente nel
perimetro {0x16E3A2, 0x16EC38, 0x16F8EC}; resta aperto **chi invoca**
setter e invoker registrati (§7).

## 7. Limiti

- Statico: nessuna esecuzione/hardware; i modelli funzionali (setter,
  normalizzatore) sono ricostruzioni semantiche verificate su finestre
  allineate e modelli esaustivi/sistematici (sweep 2^16).
- **Il setter 0x16E3A2 non ha chiamanti statici censibili**: il suo
  trigger runtime è un dispatch calcolato (punto cieco del census) oppure
  è codice morto in V1.1.
- **I consumatori delle registrazioni 0x22C3BC/0x16ACDC non sono
  identificati**: chi legge [0x5545F8+0x18] e [0x392AC0+0x1C] e chiama
  0x1406D0/0x140704 è un ulteriore strato (framework task/monitor).
- La cella case-1 0x366DDC non ha registranti nei 16 payload.
- La coppia iniziale di boot dipende da 0x22C434() (runtime, non
  derivabile).
- Census da listato lineare = candidati; i siti della catena sono
  riverificati in finestre dedicate.
- V1.1 campione vs macchina V1.0; NON_INSTALLARE; circa10% invariato.

## 8. Prossimo passo (non ripetitivo)

(a) **Chi consuma le registrazioni**: identificare i lettori di
[0x5545F8+0x18] e [0x392AC0+0x1C] (il task/monitor che attende l'evento
0x3200002 bit 10 e chiama 0x1406D0) — chiude il trigger runtime del
commit. (b) In alternativa, il gemello TIMER0 (handler 0x29F740) come
tick dello scheduler Nikon per la mappa dei servizi timer del futuro task
cooperante R3 (punto (b) dell'iterazione 29, ancora aperto).

## 9. Revisione indipendente — audit `iris-pair-audit-31` (iterazione 31), precisazioni accolte

Agente generato con tools.agents.spawn (configurazione ereditata),
lavoro in sola lettura su finestre objdump proprie + scanner
brute-force dei branch su tutti i 16 payload. Esito: **claim 1 (setter),
2 (commit), 4 (invokers, con correzioni), 5 (tabella record) CONFERMATI**;
claim 3 (normalizzatore) e 6 (conseguenza) confermati **CON PRECISAZIONI
MATERIALI ACCOLTE**; controlli extra (a)(b)(c) CONFERMATI (census
0x16F86C/0x16F8EC esatto; 0x16F90A dentro 0x16F8EC, che scrive la
coppia complementare direttamente in struct +0xC/+0x10 e setta gate=1;
zero riferimenti persi verso 0x16E3A2/0x16EC38). Precisazioni accolte e
integrate sopra + nel verificatore:

1. **bmsk_s con n maschera n+1 bit**: i campioni shift-15/20 usano
   `bmsk_s r0,r0,0x1` = &0x3 → bit campionati {15,16} e {20,21}:
   il set validato è **{7,8,12,13,15,16,20,21}**, non {…15,20}. Il
   modello e lo sweep 2^16 del verificatore sono stati corretti di
   conseguenza (ora rifiutano bit16+bit21, come il codice).
2. **Cella id-2/id-4**: 0x1405F8 case r0==4 → pool 0x14062C =
   0x366DE0; case r0==2 → pool 0x140630 = 0x366DE4. Quindi bit2 →
   0x16ECB4 e bit1 → 0x16EC88 (la prima stesura aveva le funzioni
   invertite).
3. **0x16ACDC memorizza halfword 7** a +0x14 (bmsk_s ,0x2 = &7),
   non 3.
4. **Il campione bit3 ([fp-20]) non è contato** dal loop di
   validazione; il ramo gate==1 salta magic e validazione.
5. Le `ld` iniziali da [fp-8]/[fp-4] nel setter sono carichi non
   inizializzati (morti: la coppia è riletta via 0x16F914 a ogni
   match) — innocui.
6. 0x22C3BC memorizza il puntatore a [0x5545F8+0x18] **solo se la
   cella è vuota**; nella chiamata del setup r1 diventa 1 e l'evento
   0x3200002/1<<10 viene effettivamente pubblicato.
7. Coincidenza dati p09@0xD70F6E verso 0x16F86C (regione dati fuori
   sync) non è un branch reale; il census del verificatore (forme bl)
   è esatto.

Limite della revisione (dichiarato dall'agente): sola lettura, nessuna
esecuzione; il census copre i branch diretti, non i salti indiretti.
