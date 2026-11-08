# Tabella shadow diagnostica 0x446808: scrittore identificato, servizio byte diagnostici decodificato (iterazione 26)

- **Data**: 22 ottobre 2026 (iterazione 26 del ciclo offline).
- **Ramo**: Lens MCU / iris — punto (a) aperto dall'iterazione 23
  ([completamento iris](S33_Iride_Completamento_Handler_Evento_e_Byte_Stato.md)):
  chi scrive la tabella shadow 0x446808 che il pannello diagnostico 0x2C5100 polla.
- **Tappa**: R0/R1 (percorso «ritorno pronto»; l'iris è il diaframma comandato).
- **Verificatore**: [s33_verify_lens_iris_shadow.py](../Python_Trace_Scripts/s33_verify_lens_iris_shadow.py)
  → **PASS_IRIS_SHADOW_STATIC**, evidenza
  [20261022T013010Z](../Risultati/Lens_MCU_Interface/Iris_Shadow/20261022T013010Z/)
  (`iris_shadow.json`, `gnu_windows.txt` 19 finestre, `script_snapshot.py`).
  Le cartelle 012859Z–013000Z sono corse di calibrazione della stessa sessione
  (limm a 0x16F646 non 0x16F648; `\b` dopo `]` rimosso; sezione mask writer
  riscritta sulla finestra reale); **013010Z è l'unica evidenza valida**.
- **Grado di certezza**: byte-exact per le finestre assertite; censimento da
  listato lineare = candidato; modello funzionale = ricostruzione semantica.
  Statico, nessun hardware. NON_INSTALLARE. Circa 10% invariato.

## 1. Risposta breve

Lo scrittore del byte valore della tabella shadow 0x446808 è **un solo
servizio: 0x16F72C(secondary=r0, idx=r1, value=r2, flag=r3)**, con la store
`stb_s r2,[0x446808+4·r1+0]` a 0x16F742 (pool 0x16FA34) e **nessun range
check prima dello store**. La tabella è azzerata dall'init **0x16F638**
(chiamato da 0x15AF58) con un loop hardware `lp` a 128 iterazioni e un
**LIMM 0x446808** (byte `44 00 08 68` a 0x16F646, middle-endian: l'unico
limm della tabella in tutti i 16 payload). Il pannello 0x2C5100 **non legge
telemetria**: le voci 8/9/0xA che polla sono **flag di richiesta** che il
pannello stesso serve imponendo `0x18B85C(1)` (Big) o `0x18B85C(9)` (Small).

## 2. Il servizio byte diagnostici (famiglia 0x16F6xx–0x16FAxx)

La tabella non è iris-specifica: è il **cache di byte diagnostici** di un
servizio generale, di cui l'iris è solo uno dei consumatori.

- **Tabella shadow 0x446808**: 128 voci × 4 byte = `{valore byte+0,
  secondario byte+1, flag halfword+2}`; init `{0, 0xFF, 1}`.
- **Tabella handler 0x446A08** (subito dopo: 0x446808+512): 10 word di
  puntatori a funzione, azzerata dall'init via `0xAD90C(dst,·,0x28)`.
- **Getter 0x16F920** (522 siti bl su tutto il firmware): due ingressi:
  - 0x16F920 = **raw**: `ldb [0x446808+4·idx]`, ritorno diretto;
  - 0x16F928 = **pending**: idx≥0x61→0; byte+1 (secondario) 0xFF→0; altrimenti
    bit15 dell'halfword `[record+20·secondario+0xA]` (pool 0x16FA44 =
    cella 0x3678E8 = puntatore tabella record).
- **Scrittore 0x16F72C** (19 siti bl): store del valore, poi log
  `id=(idx<<7)|1` e **dispatch 0x16F6B0** sui 10 handler registrati.
- **Flag setter 0x16F950(idx, on)** (7 siti): bit0 dell'halfword+2.
- **Register/unregister handler**: 0x16F988 (find-or-insert, 2 chiamanti:
  0x16E30A e 0x323856) e 0x16F9F0 (azzera lo slot, zero chiamanti bl);
  dispatch 0x16F6B0 con 7 chiamanti, due fuori famiglia (0x20F74E,
  0x26C5C2).

## 3. Il layer record: da dove arrivano i valori

- **Installazione**: init **0x16E2F4** (chiamato da 0xC5D9E) passa la
  **tabella record 0x392F04** (pool 0x16E388) con count 0x10 a
  **0x16F66C**, che per ogni record i scrive `shadow[rec.idx].secondario=i`
  e compila la struct **0x3678E4**: `{+0 byte enable=1, +4 (cella 0x3678E8)
  = puntatore tabella, +8 halfword count, +0xA byte gate, +0xC/+0x10 coppia
  di stato a 64 bit}`. Registra anche l'handler **0x16E588** (pool
  0x16E38C) via 0x16F988.
- **Record** (16 × 20 byte, fine 0x393044 = pool 0x16EDD4):
  `{maskLo@+0, maskHi@+4, valore@+8, idxShadow@+9, half@+0xA (bit15
  pending), half@+0xC}`.
- **Consumatore transizioni 0x16F86C(newLo, newHi, flag)** (3 chiamanti:
  0x16E3FA, 0x16EC74, 0x16F90A): gate `[0x3678E4+0xA]`, legge la vecchia
  coppia +0xC/+0x10 e committa la nuova; un record «match» se
  `(mask0 & (oldLo^newLo)) | (mask4 & (oldHi^newHi)) != 0`, e per ogni
  match chiama `0x16F72C(recIdx, rec.idx, rec.value, flag)`.
  **0x16F8EC(pair)** scrive la coppia *complementare* (+0xC/+0x10) e
  pone il gate=1: tutti i bit risultano cambiati → tutti i record con
  maschera non nulla sparano. 0x16F914 = lettura mascherata della coppia.
- In sintesi: **la shadow è l'uscita cache di una macchina a stati a 64
  bit**: i byte diagnostici cambiano quando cambia la coppia di stato.

## 4. Il pannello iris 0x2C5100 ridefinito

Sequenza byte-exact (getter via pool 0x2C519C):

1. prologo: poll voci **4** e **7** (loop until-zero) con chiamate
   `0x18B794` e `0x18B72C`;
2. attende che la **voce 8** si azzera, poi `0x18B72C`;
3. **voce 9 ≠ 0** → log → **`0x18B85C(1)`** (imponi Big) → attende che la
   voce 9 si azzera;
4. **voce 0xA ≠ 0** → log → **`0x18B85C(9)`** (imponi Small) → attende che
   si azzera; altrimenti ricomincia.

Le voci 8/9/0xA sono dunque un **canale di richiesta** verso il pannello,
non lo stato dell'iride verso l'UI: la frase dell'iterazione 23 «polla i
byte shadow e poi impone» è confermata e precisata nella direzione
richiesta→servizio. Nessun chiamante statico di 0x16F72C scrive 8/9/0xA
(gli indici espliciti sono solo {1, 2, 0xC, 0x62, 0x65, 0x66, 0x77}); le
richieste arrivano a runtime dal layer record o dal dispatcher comandi
0x16E440 (switch su `0xCAD30()-3`, ~0x44 casi, solo classificato).

## 5. Census (verificatore, sezione 18)

- pool LE esatti 0x446808: **solo {0x16FA34, 0x16FA3C}** in payload0, zero
  negli altri 15 payload;
- limm middle-endian 0x446808: **solo 0x16F646** (straddle 0x16FA32 fra i
  pool adiacenti 0x16FA30/0x16FA34, classificato);
- regione [0x446808, 0x446A30): solo i 4 pool di famiglia
  {0x16FA30→0x446A08, 0x16FA34, 0x16FA3C, 0x16FA60→0x4469F8};
- chiamanti: 0x16F72C = 19 siti (mappa indici nel JSON), 0x16F638 =
  {0x15AF58}, 0x16E2F4 = {0xC5D9E}, 0x16F66C = {0x16E306}, 0x16F86C =
  {0x16E3FA, 0x16EC74, 0x16F90A}, 0x16F6B0 = 7 (2 fuori famiglia),
  0x16F988 = {0x16E30A, 0x323856}, 0x16F950 = 7 (una coppia in payload2),
  0x16F9F0/0x16FA66 = nessun bl; 0x16F920 = 522 siti; 0x16F964
  (scrittore byte cella 0x3678F9) = 58 siti, due tail-call `b.d` nel
  blocco AE (0x149F80, 0x14A45C).

## 6. Derivazione da annotare (inferenza, non regola provata)

Il dispatch legge gli handler a `[0x446808+4·i+512]` (`ld.as [r1,128]` →
tabella 0x446A08, aritmetica indipendente). Il register/unregister usa il
pool 0x16FA60 = 0x4469F8 con `sub3 r?,r?,0x3e` e lo stesso `ld.as +512`:
le due vie convergono su 0x446A08+4·slot **solo se** l'immediato stampato
0x3e contribute 0x1F0 (scala ×8). La semantica find-or-insert richiede la
convergenza; la scala dell'immediato di `sub3` resta una **derivazione**.

## 7. Limiti

- Statico: nessun hardware/runtime; il modello funzionale è ricostruzione.
- **Il contenuto della tabella record 0x392F04 è RAM**: quale record porta
  idx 8/9/0xA e con che valore/maschere non è derivabile staticamente
  (nessuno scrittore statico del contenuto nei 16 payload); l'origine
  runtime delle richieste al pannello resta APERTA. Il dispatcher comandi
  0x16E440 è solo classificato come produttore candidato.
- La store di 0x16F72C non ha range check su idx: un idx fuori range
  scriverebbe oltre le 128 voci (disciplina dei chiamanti non provata).
- sub3 ×8 = derivazione (sopra).
- Census da listato lineare = candidati; i siti della catena sono
  riverificati in finestre dedicate (19 finestre in `gnu_windows.txt`).
- V1.1 campione vs macchina V1.0.

## 8. Prossimo passo

(a) Decodificare il **dispatcher comandi 0x16E440** (switch su
`0xCAD30()-3`, jump table byte-offset 0x16E46C con `add1_s` ×2, ~0x44
casi): è il candidato produttore di cambi di stato/record e chiude il
ciclo «chi genera le richieste 8/9/0xA». (b) In alternativa il
**consumatore runtime della tabella slot 0x4437F4 / interrupt TIMER1**
(secondo punto aperto dell'iterazione 23). Entrambi offline e
byte-verificabili.

## 9. Revisione iterazione 27 — audit indipendente `iris-shadow-audit-27`, precisazioni accolte

Audit byte-level su finestre objdump rigenerate indipendentemente (evidenza
iterazione 26 rigenerabile: le 19 finestre coincidono istruzione per
istruzione). Verdetto: claim 1–4, 6, 8 CONFERMATI; claim 7 CONFERMATO CON
PRECISAZIONE; **claim 5 corretto in un sotto-punto**; un «limite» del §7 è
**contraddetto**. Il coordinatore ha riverificato sui byte le correzioni
chiave prima di accoglierle. Script `Python_Trace_Scripts/s33_verify_lens_iris_shadow.py`
corretto (mappa EXPLICIT_IDX) e rieseguito PASS:
prove `Risultati/Lens_MCU_Interface/Iris_Shadow/latest.json`
(**evidenza valida 20261022T014758Z post-audit**; la 013010Z resta quella
pre-audit della sessione 26).

- **CORREZIONE semantica campo record+8**: nel consumatore 0x16F86C il
  terzo argomento passato a 0x16F72C NON è `rec.value` "valore costante":
  dopo il match il codice calcola `(maskHi&newHi)<<32 | (maskLo&newLo)` e
  chiama **0x335C4C = `__lshrdi3`** (`bl.d` con delay slot
  `ldb_s r2,[r13,8]`), poi **`extb_s r2,r0`**: il byte scritto è
  **`bit<rec[+8] & 0x3F>` della nuova coppia di stato a 64 bit**. Il campo
  +8 è la POSIZIONE DI BIT, non il valore. Conferma indipendente dal
  contenuto statico (punto sotto): in tutti i 16 record la maschera ha un
  solo bit e +8 è esattamente la posizione del bit (coerenza 16/16).
- **CORREZIONE del limite §7 «contenuto 0x392F04 RAM non derivabile»**:
  0x392F04 cade dentro il payload1 caricato [0x360800, 0x428600) (offset
  0x32704, blocco sha-verificato) ed è **dato inizializzato staticamente**:
  16 record ben formati, stringa "Write ok!" subito dopo a 0x393044.
  Contenuto verificato dal coordinatore:
  **rec[1] {maskLo 0x00010000, +8=0x10, idx=8}, rec[2] {maskLo 0x00200000,
  +8=0x15, idx=9}, rec[3] {maskLo 0x00008000, +8=0x0F, idx=0xA}** →
  **shadow[8/9/0xA] = bit 16/21/15 della coppia di stato a 64 bit**.
  L'«origine delle richieste 8/9/0xA» si chiude staticamente per la parte
  di mappatura: le richieste sono bit della macchina a stati, non dati
  runtime non derivabili. Resta runtime CHI setta/azzera quei bit della
  coppia (il classificatore 0x16E440 — vedi iterazione 27 — non è un
  produttore) e l'eventuale sovrascrittura della tabella (nessuno
  scrittore statico trovato).
- **CORREZIONE mappa EXPLICIT_IDX** (2 voci): 0x16E8F6 = **0x77** (non
  dinamico; `mov_s r1,0x77` a 0x16E8F2) e 0x16EF7A = **0x65** (non 0x66;
  `mov_s r1,0x65` a 0x16EF78). Insieme degli indici espliciti invariato:
  {1, 2, 0xC, 0x62, 0x65, 0x66, 0x77}; conclusione «nessuno scrittore
  statico scrive 8/9/0xA» invariata.
- **Precisazioni minori accolte**: (a) «scrittore unico del byte valore»
  va letto salvo l'init 0x16F638, che scrive byte+0 a zero nel loop
  (0x16F64E); census store della famiglia: byte+0 solo a 0x16F64E (init) e
  0x16F742 (writer). (b) il log in 0x16F72C è condizionato (value≠0,
  idx<0x61). (c) sub3(0x3e) con scala ×8 è **regola ISA documentata**
  (ARCompact Programmer's Reference: `dest←src1−(src2<<3)`), non
  derivazione: la convergenza register/unregister → 0x446A08+4·slot è
  byte-provata; anche la via insert (pool 0x16FA30 + add2_s) conferma la
  stessa aritmetica di slot. (d) Pannello: **0x2C5100 non è un ingresso**
  (`mov r4,0x1` in mezzo al flusso); la funzione contenitore è
  **0x2C5074** (`push_s blink`), il loop di servizio è
  **0x2C50B6–0x2C517E**; zero riferimenti statici a 0x2C5100/0x2C50B6.
  (e) 0x16F928 è ingresso secondario senza chiamanti bl diretti (via
  puntatore). (f) 0x149F80/0x14A45C sono nel cluster servizi AE
  0x149xxx, fuori dal blocco AE/iris 0x123000–0x126000.
