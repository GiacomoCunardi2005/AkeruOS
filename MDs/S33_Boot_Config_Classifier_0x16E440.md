# Classificatore di configurazione boot 0x16E440: byte del record TBIB 8, mappa completa e chiamanti (iterazione 27)

## 1. Risposta breve

L'«dispatcher comandi 0x16E440» lasciato aperto dall'iterazione 26 è un
**classificatore puro**: mappa un byte di configurazione del **record TBIB
8** (payload 8, base 0x00C8E800, tipo 1, 0x600 byte) su un piccolo codice
enumerativo. **Non è un produttore di cambi di stato/record**: non scrive né
shadow né record — la candidatura dell'iterazione 26 è ridefinita in
negativo. L'iterazione 27 ha inoltre accolto l'audit indipendente
dell'iterazione 26 (vieni [revisione](S33_Iride_Shadow_0x446808_Scrittore_e_Servizio_Diagnostico.md) §9),
che ha chiuso staticamente l'origine delle voci shadow 8/9/0xA: **bit
16/21/15 della coppia di stato a 64 bit** (record statici in payload1).

Fonti: [script](../Python_Trace_Scripts/s33_verify_boot_config_classifier.py),
[prove](../Risultati/Boot_Config/Classifier/latest.json)
(**evidenza valida 20261022T014741Z**; le cartelle 014519Z–014726Z sono
calibrazioni della stessa sessione), finestre GNU allineate in
`Risultati/Boot_Config/Classifier/20261022T014741Z/gnu_windows.txt`.
Agente usato: `iris-shadow-audit-27` (audit dell'iterazione 26, verdetto
integrato nel §9 del rapporto shadow).

## 2. Il classificatore 0x16E440

Byte-exact (finestra allineata 0x16E440–0x16E520):

- Prologo GCC (`sub_s sp,sp,8`, `push_s blink`, `st.aw fp`, `mov fp,sp`);
  salva `r0→[fp,8]` e `r1→[fp,12]` e **non li rilegge mai**: gli argomenti
  sono morti (a0/a1 ignorati).
- `bl 0xCAD30` → `sub_s r0,r0,3` → `cmp_s r0,0x43` → `bhi` ritorno 0;
  altrimenti **jump table 68 voci a 0x16E46C** (byte-offset con `ldb.x` +
  `add1_s` ×2, stessa tecnica del dispatcher tuning 0x80F9C8).
- Ogni caso è `mov_s r0,K; b` sull'epilogo comune; default/fuori range → 0.
  Non scrive memoria: solo `return code`.

## 3. Il getter 0xCAD30 e il byte 0xC8E80C

`0xCAD30`: `ld.as r0,[pcl,-155]` (campo SIMM9_8 = −155 dai mezzeway raw
`1765 f600`) → pool **(PC&~3)+4·(−155) = 0xCAAC4** → word LE **0x00C8E80C**;
`ldb_s r0,[r0,0]`; ritorno. Regola ld.as scalata riverificata su tre siti
indipendenti (0x16E528→0x16E388=0x392F04; 0x20EDB4→0x20EB6C=0x36972C;
0xCAD30→0xCAAC4): objdump stampa l'indirizzo NON scalato.

**0xC8E80C = payload 8 + 0xC**. Payload 8 = record TBIB tipo 1, 0x600
byte, stringa «NotRunOneCard», header `{0x5FA3, magic C1C2C3C4, 0x287,
0x2C, 0x301, 0x1E0002, 1}`; 224 riferimenti pool dal Main; famiglia di
accessor per i byte header (+0xC/+0xD/+0xE, pool 0xC9CB0/0xC9CBC/0xC9CC8).
Census LE della word 0xC8E80C: esattamente 8 pool in payload0
{0xC9CB0, 0xCA5D0, 0xCAAC4, 0xCB578, 0xCE3A8, 0xD04D8, 0xD0A5C, 0xD1014},
zero negli altri 15 payload. Gemelli: setter 0xCB7E4 (ld.as −157 → pool
0xCB578) scrive [0xC8E812].

## 4. Mappa completa byte → codice

25 valori non-zero su 68 casi (tutti gli altri → 0), verificata per tutti
i 68 casi e modelizzata su 256 valori:

| byte | codice | byte | codice | byte | codice |
|---|---|---|---|---|---|
| 0x03 | 5 | 0x11 | 9 | 0x2C | 7 |
| 0x05 | 14 | 0x12 | 27 | 0x33 | 33 |
| 0x07 | 13 | 0x14 | 23 | 0x3B | 18 |
| 0x09 | 19 | 0x17 | 24 | 0x40 | 16 |
| 0x0A | 6 | 0x20 | 9 | 0x41 | 2 |
| 0x0B | 8 | 0x23 | 26 | 0x42 | 1 |
| 0x0D | 25 | 0x25 | 8 | 0x44 | 20 |
| 0x0E | 16 |  |  | 0x46 | 32 |
| 0x0F | 22 |  |  |  |  |
| 0x10 | 21 |  |  |  |  |

**Col campione V1.1 il byte vale 0x2C → il classificatore ritorna 7**
(end-to-end: `classify(byte[record8+0xC]) == 7`).

## 5. Chiamanti

Census lineare: esattamente 5 siti; 4 verificati in finestre allineate, 1
falso positivo dati.

| Sito | Payload | Funzione | Azioni sul risultato |
|---|---|---|---|
| 0xCA284 | 0 | 0xCA274 | codice 5 → setter 0xCAD38(1) + richiesta UI 0x1453E4(0x87, 0); 7 → getter flag 0xCAD5C → (0x87, 1/2); default → (0x87, 7) |
| 0x20EDE0 | 0 | 0x20EDC4 | 5 → 0x1453E4(0x7E, 0); 7 → (0x87, 2); default → (0x5E, 0); usa anche 0xCAD5C/0xCBDF8/0x177030 |
| 0x7FF6C2 | 4 (tuning) | 0x7FF680 | confronta il flag 0xCAD5C (==2): → 0x169F40 con richiesta 0x5E o 0x87 e telemetria shadow[0x65] |
| 0x800174 | 4 (tuning) | 0x800158 | codice 0xC → dispatch 0x169D78(0, 2\|1<<14, 0x16); else → 0x20E814(a0,a1,a2) |
| 0xDC0B74 | 9 (Resource) | — | **falso positivo dati**: word LE 0xD6F900CD che si decodifica come `b.d 0x16E440`; la finestra allineata contiene un'istruzione impossibile (`fmul.f` che scrive pcl) e .word dati; zero rami in ingresso |

Pattern condiviso nei 4 chiamanti reali: `mov r0,0x61; bl 0x16F920`
(getter shadow[0x61]) → `r1=0` → `bl 0x16E440` → confronti con
5/7/0xC → richieste UI 0x1453E4(0x87, 0..7) o dispatch. Il fetch di
shadow[0x61] è **inerte** per il classificatore (argomenti ignorati):
pattern compilato condiviso, non canale dati.

## 6. Conseguenze per l'iterazione 26 (shadow iris)

- **0x16E440 non è il produttore delle richieste 8/9/0xA**: è un
  classificatore senza scritture. L'origine delle voci 8/9/0xA è chiusa
  dall'audit: record statici payload1 → bit 16/21/15 della coppia di
  stato; resta aperto chi setta quei bit a runtime.
- Con V1.1 il classificatore ritorna 7 e i chiamanti pubblicano
  richieste UI 0x87 con argomento 2 (o 1/7): coerente con una selezione
  di «modalità prodotto/regione» dal record 8; il nome fisico del byte
  resta APERTO (inferenza: configurazione di variante/modello).
- NB strumentale: errore di aritmetica esadecimale iniziale
  (0xCAD30−0x26C = **0xCAAC4**, non 0xCAC64) aveva fatto apparire il
  pool come «codice»: conferma che i pool ld.as vanno sempre riletti
  dai byte con la regola scalata prima di classificare.

## 7. Limiti

- Statico: nessun hardware/runtime; il record 8 runtime potrebbe
  differire dal campione V1.1 (loader TBIB).
- Semantica fisica del byte 0xC8E80C e dei codici (5/6/7/…) non
  derivabile staticamente; le richieste UI 0x87/0x7E/0x5E e i dispatch
  0x169D78/0x20E814 sono ancore dai checkpoint precedenti, non ridecificati.
- Campione V1.1 vs macchina V1.0: indirizzi non portabili senza prova.
- I censimenti da listato lineare restano di grado «candidato»; i 4
  siti codice e i 3 pool della catena sono riverificati in finestre
  dedicate.

## 8. Prossimo passo

(a) **Consumatore runtime della tabella slot 0x4437F4 / interrupt TIMER1**
(secondo punto aperto dell'iterazione 23, ancora vergine): chi scade gli
slot e chiama gli handler differiti. (b) In alternativa, i tre chiamanti
del consumatore 0x16F86C (0x16E3FA, 0x16EC74, 0x16F90A) per capire chi
muove la coppia di stato 64-bit da cui nascono i bit 16/21/15 delle
richieste iris. Entrambi offline e byte-verificabili.
