# Famiglia `muldw` / `muludw` / `mulrdw`: studio statico dell'uso nel firmware

8 novembre 2026. Solo analisi statica del blocco verificato 0 (`0x000AD800`, 0x2AE400 byte) del firmware originale V1.1. Nessun firmware, emulatore o hardware toccato. Certezza **A** = byte/disassemblato, **B** = dedotto dall'uso del compilatore, **C** = ipotesi.
Prosegue [MULUDW_SEMANTICS.md](MULUDW_SEMANTICS.md) (3 punti) e la [validazione del 6 novembre](S33_GUI_Integrazione_Manager_Nikon_e_Validazione_muludw_20261106.md) (helper `0x3342A8`).

Riproduzione: `python3 Python_Trace_Scripts/s33_census_muldw_family.py` → `Risultati/Analisi_Statica/Muldw_Census_20261108/census.json` (elenco completo dei siti).

## Nomi e codifica (A)

Opcode maggiore 5, formato a 32 bit, sub-opcode nei bit 21–16: `muldw` = 0x0C (con segno), `muludw` = 0x0D (senza segno), `mulrdw` = 0x0E (arrotondato). Forma usata: `mul?dw 0,b,c` (A = 62, destinazione scartata, nessun `.f`). Il risultato si legge solo dagli accumulatori r56/r57. Nel simulatore GNU sono enumerati come `X05_MULDW/MULUDW/MULRDW`, ma senza semantica originale.

## Quanto è usata (A, euristica: dest 0 + lettura r56/r57 entro 3 istruzioni)

| | decodificate | reali | lette da r57 | da r56+r57 | precedute (≤4) da `sr …,[aux_macmode]` |
|---|---|---|---|---|---|
| `muldw` | 280 | **234** | 234 | 0 | 168 |
| `muludw` | 1456 | **1343** | 1214 | 129 | 970 |
| `mulrdw` | 4 | 0 | – | – | – |

I documenti precedenti ne conoscevano 3. È un primitivo che il compilatore genera in tutto il codice principale, non un'ottimizzazione isolata. `mulrdw` non ha usi reali (le 4 istanze sono dati decodificati come codice).

## Che cosa calcola, secondo il codice che la usa (B)

- **Scelta del compilatore:** gli operandi di `muludw` provengono da estensioni senza segno (`ldb`, `ldh`, `extw`) in 1052 casi su 1053; quelli di `muldw` da estensioni con segno (`sexw`, `ldh.x`, `ldw_s.x`) in 139 casi, e da valori senza segno ≤ 16 bit in 79 casi (byte, 16 bit, positivi nelle corsie con segno). Quindi `muldw` è il prodotto 16×16→32 **con segno**, `muludw` quello **senza segno**.
- **Risultato:** dopo `muldw` si legge **solo r57**, mai r56. Ne segue (B) `r57 = sext16(b[15:0]) · sext16(c[15:0])` come intero a 32 bit, con MACMODE 0. r56 (corsia alta) è scartato. È invece usato da `muludw` soltanto nell'helper 32×32 (`0x3342A8` e copie inline: 129 siti).
- **Idiomi reali:** somma di quadrati (`0x17EBB8`, `0x1FF4BE`: `muldw x,x` + `muldw y,y`), miscelazione di byte `(0xFF−p)·q+16 >> 5` (`0x11CD2C`), scalatura in loop a zero overhead con `sth r57` (`0x1D211A`), forma con limm `muldw 0,0x2,r4` (`0x2741E4`).
- **Accumulazione:** `macudw` dopo `muludw` accumula nella stessa corsia: il ridimensionatore a `0x272E70…0x273D68` somma byte×pesi Q15 (somma pesi 0x8000) e poi legge `asr r57,15` (B).

## `aux_macmode` (A)

- 1207 scritture `sr 0,[aux_macmode]` prima di uso DSP: il codice non presume lo stato del chiamante.
- Gestore IRQ (`0x2645C8…0x265ED0`) e cambio contesto task (`0xB30DE`/`0xB2EAA`) salvano e ripristinano macmode, r56, r57, xmac0–2. Quindi r56/r57 sono stato per contesto, e un modello che li perde fra interrupt è sbagliato.
- Il bit 3 (`or …,0x8`) è attivato soltanto nei 7 siti del ridimensionatore (`0x272E74`, `0x272F4C`, `0x272F90`, `0x273140`, `0x273D14`, `0x273D38`, `0x273D64`) e non viene azzerato lì. Il suo significato (saturazione?) è **C**. Con byte×Q15 i valori restano ≤ 0x7F8000, per cui la saturazione a 32 bit non scatterebbe.

## Conseguenze per l'emulatore v7 (A sul codice della patch, B sull'effetto)

`arc700-gnu-simulator/patches/s33-dsp-v7-experimental.patch` implementa solo forma reg-reg, A=62, no `.f`, MACMODE 0 visto, e:
- `muldw`: dominio **solo operandi 0…0x7FFF oppure un operando zero**. Gli operandi negativi estesi con segno (frequenti: `sexw` dopo `sub`, es. `0x17EBAC`) producono `S33_DSP_GUARD` e uno stop, non risultati sbagliati.
- non decodifica 6 siti `muldw` (4 con limm, 2 con registro ≥ 32) e 12 `muludw` in forma u6;
- non implementa `macudw`/`macdw`, né MACMODE ≠ 0 (il ridimensionatore viene rifiutato).

Estensione possibile, **non applicata e non convalidata**: con segno `r57 = sext16·sext16`, r56 analogo sulla corsia alta. È coerente con l'uso del compilatore, ma l'unico riscontro indipendente resta il prodotto doppio con segno di MAME e il brevetto ARC. Manca ancora la definizione ARCv1 DSP, e non c'è prova di saturazione o arrotondamento. GCC ufficiale non emette `muldw` (ricerca dell'8 novembre 2026). Il firmware è probabilmente compilato con MetaWare, ma questo non è stato verificato.

## Limiti

Disassemblaggio lineare: le euristiche "reali" possono includere o escludere pochi siti. Solo il blocco 0 (gli altri blocchi di tipo 0 sono dati: i loro conteggi grezzi non sono codice). Nessuna osservazione della CPU fisica né esecuzione nuova. NO-GO flash invariato; NON_INSTALLARE.

## Tentativo di convalida dal dump hardware v5 (8 novembre 2026, esito negativo)

Il dump `Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN` (SHA `c91888b2…6107`) è stato esaminato offline per cercare osservazioni reali di r56/r57:
- **Operandi a indirizzi fissi:** 8 siti (`0x1C77B8`, `0x1C9F5E`, …, `0x293A14`) con entrambi gli ingressi a halfword globali `0x368Axx`/`0x36C28x`. Nel dump valgono tutti 0 e nessun sito salva r57 a un indirizzo noto.
- **Frame dei task:** formato IRQ (`0xB3054`) di 164 byte: r0–r3@0–12, r12@16, pc@52=ilink@56, r4–r11@60–88, macmode@140, r56@144, r57@148, xmac0–2@152–160. Il cambio volontario `0xB2C74` salva r13–r25/gp/fp ma **non** macmode/r56/r57. Al momento del dump tutti i task tranne idle sono sospesi volontariamente: i loro offset 140–148 sono residui.
- **Frame residui sugli stack:** 102 candidati, 8 con r56/r57 non nulli, tutti falsi positivi (status32 0 o incoerente, ASCII nei registri, pc non dopo una `mul*dw`).

Il dump non contiene un'osservazione utilizzabile. Codex (`Risultati/Codex_Risposte/muldw_prova_hw_20261108.md`) conferma che non esiste un test DSP su fotocamera già pronto; l'infrastruttura MEMDUMP v5 è riutilizzabile solo con autorizzazione esplicita.
