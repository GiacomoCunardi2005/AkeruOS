# Iris: attuazione GPIO diretta su 0x0FF04024 e chiusura negativa del «wrapper iris»

**Iterazione 21 — 22 ottobre 2026.** [Script](../Python_Trace_Scripts/s33_verify_lens_iris_actuation.py), [prove](../Risultati/Lens_MCU_Interface/Iris_Actuation/latest.json) (**evidenza valida 20261022T005922Z**, PASS exit 0, post-integrazione dell'audit; la 20261022T005612Z della stessa sessione era la calibrazione pre-audit, cartella rimossa).

## 1. Domanda

Chiudere il punto aperto più vecchio del ramo obiettivo: **quale dei 33 chiamanti della
transazione 0x25F338 è il wrapper iris** (BCIP_Aperture 0x9208, 1:Big 9:Small), punto
rinviato dalle iterazioni 1–19 (vedi [classificazione wrapper](S33_Vibe_Blocco_Riparazione_Wrapper_Obiettivo.md)
e [contesti/API stato](S33_Obiettivo_Contesti_Parametri_e_API_Stato.md)).

## 2. Risultato in sintesi

Il wrapper iris **non esiste**: l'iride NON viaggia sulla transazione wire MCU
0x25F338/porta 0x0FF05000. È attuata da **GPIO diretti**: bit4 (Big) e bit3 (Small)
del registro **0x0FF04024**, con pulizia dei bit0/1 di **0x0FEF0388** prima della
mossa. Due affermazioni storiche sono quindi CORRETTE in senso opposto:

- «nessun GPIO iris-specifico» ([diaframma/iride](S33_Diaframma_Iride_Stati_Big_Small_e_Comando_BCIP.md))
  è **CONTRADDETTO**: bit3/bit4 di 0x0FF04024 sono esattamente i GPIO iris;
- la freccia «AE/iris (0x1236BC) ──▶ hub OM (0x1EE148/…)» del rapporto contesti/API
  stato **non è un percorso statico dimostrato**: nessun `bl` dal blocco AE/iris
  0x123000..0x126000 raggiunge alcun entry del cluster wire (censimento negativo
  byte-assertito). Era inferenza.

L'encoding **1 = Big / 9 = Small** di BCIP_Aperture SP2 è confermato al livello
attuazione (`cmp idx,0x9` seleziona il percorso Small), coerenza con gli indici
r19∈{1,9} del blocco AE e col pannello diagnostico che chiama il setter con 1 e 9.

## 3. Catena byte-exact (payload0, base 0x0AD800)

```
AE 0x124D8A / 0x124E04   mov r19,0x9; mov r0,9; bl 0x149530      (log "Change Iris
AE 0x124EEA              cmp r15,9; mov r0,r15; bl 0x149530       from MAX → MIN"
        │                formati: pool 0x124F64/0x124F6C → stringhe payload1
        ▼                 0x3860EE/0x38612C, verificate raw)
0x149530(idx)            wrapper API (push blink+r13): r13=idx; bl 0x18B85C;
        │                r0=1 sempre (il ritorno del setter è scartato); coda 0x149362
        ▼
0x18B85C(idx)            stato: byte [0x367FE8+2]; se idx==stato ritorna;
        │                0x235A1C(2,&h) [fallimento → ritorna il corrente, senza
        │                 release]; 0x235DA0() [fallimento → 0x23524C(2) e ritorna
        ▼                 il corrente]; se la request fallisce: 0x18B9D4
0x235B0C(h, idx, 1, 0x3A98)  (iris entrambi i bit + delay 500 via 0x2359B0,
        │                0x23524C(2), 0x235DE8) e ritorna il corrente
        │                PRE-GUARDIA (0x235B28): bl_s 0x235ABC confronta h con
        │                [0x36A480]; se diverso → ritorna 0 SENZA attuare;
        │                sezione critica 0x1786E8/0x179354;
        │                busy check 0x234F1C([[0x3EBD3C]+8]); se occupato:
        │                  [0x36A482] = 0x15 e salta l'attuazione;
        │                cmp idx,0x9 ──┐
        ▼                           │
0x235950 (SMALL, idx==9)   0x2358F4 (BIG, idx!=9)
  callback [0x36A464+0x40]    callback [0x36A464+0x40]
  0x0FEF0388: bclr bit0,bit1   0x0FEF0388: bclr bit0,bit1
  0x0FF04024: and -25          0x0FF04024: and -25
              + bset bit3                  + bset bit4
  → bit3=1, bit4=0             → bit4=1, bit3=0
  [0x36A464+6] = 1              [0x36A464+6] = 1
        │                           │
        └───────────┬───────────────┘
                    ▼
  contatore [[0x36A464]+0x1c]++; evento 0x158CE0(1|1<<25, 0x10);
  mailbox 0x145F28(0x36A494, 0x235AF8|0x235AE4, 0x3A98, 0);
  se wait!=0 e successo: 0x158D04(1|1<<25, 0x10, 1, 0)  [attesa completamento]
```

Il pannello diagnostico **0x2C5100** («Iris status: Big/Small», stringhe payload1
0x406E89/0x406E9A) usa lo stesso setter: `bl 0x18B85C(1)` per Big e
`bl 0x18B85C(9)` per Small, poi interroga lo stato col getter a indici 8/9/0xA.

Semantica del RMW modellata su tutti i 65.536 valori: `and -25` pulisce bit3/bit4,
`bset bitN` ne accende esattamente uno (Big e Small mutuamente esclusivi per
costruzione).

## 4. Census del registro 0x0FF04024 (payload0)

La word LE 0x0FF04024 compare in **13 pool**, tutti classificati su finestre
allineate (pool → sito utente → uso):

| Pool | Sito | Uso |
|---|---|---|
| 0x17B5F4 | 0x17B5EE | lettura bit0 (bmsk_s 0) |
| 0x234DD4 | 0x234DD0 | RMW con maschera da registro r13 (fn 0x2349C0; scrive anche 0x0FF0402C bit 11/13/14) |
| 0x23544C | 0x235446 | set ENTRAMBI bit3/4 (`or 0x18`) |
| 0x235734 | 0x23572A | set bit4 (Big) + store byte [struct+5] |
| 0x2357A8 | 0x23579C | set bit3 (Small) + store byte [struct+5] |
| 0x2357D8 | 0x2357D2 | set entrambi + attesa 0x23C620(500) |
| 0x235868 | 0x235862 | pulisce ENTRAMBI (`and -25` da solo) |
| 0x235930 | 0x23592A | **percorso Big della request 0x235B0C** |
| 0x235990 | 0x23598A | **percorso Small della request 0x235B0C** |
| 0x2359CC | 0x2359C4 | set entrambi + attesa 500 |
| 0x235BE8 | 0x235BE2 | pulisce entrambi (tail della request) |
| 0x25A008 | 0x25A004 | lettura bit1 (btst_s 0x1; legge anche 0x0FF04000 bit13) |
| 0x25E0C0 | 0x25E0BA | lettura bit7 (lens-ready, getter 0x25E0B8, invariato) |

I bit3/4 sono quindi scritti **solo** dalla famiglia iris 0x234Dxx–0x235Dxx
(oltre ai due percorsi Big/Small: sibling che li accendono entrambi — probabile
park/brake o init — e sibling che li puliscono; ruolo AE di questi sibling non
decodificato in questa iterazione). Caveat: la RMW a maschera registro in
0x2349C0 potrebbe toccare bit3/4 a runtime.

Census dei chiamanti (listato lineare GNU, tutti i siti della catena riverificati
in finestre dedicate): **32** siti `bl 0x149530` (di cui 10 nel blocco AE/iris),
**21** siti `bl 0x18B85C` (inclusi i due del pannello 0x2C5100 e la famiglia di
script diagnostici 0x2FC/0x2FD), **2** siti `bl 0x235B0C` (0x18B8AC e il fratello
0x18B9AE), **1+1** per i percorsi 0x2358F4/0x235950 (solo dalla request).
**Zero** `bl` dal blocco AE/iris verso qualsiasi entry wire.

## 5. Comandi ed esiti

- `python3 Python_Trace_Scripts/s33_verify_lens_iris_actuation.py` →
  **PASS_IRIS_ACTUATION_STATIC 20261022T005922Z**, exit 0 (evidenza valida
  post-audit; conferma finale identica 20261022T010038Z, ultima cartella). Correzioni di collaudo della prima stesura (nessuna asserzione
  indebolita): offset decimali dei `bl` ai tre siti AE (149416/149292/149064);
  regex `\b` dopo `]` rimossa (mai valida); finestra Big estesa a 0x235950 per
  includere la `b` di coda; `ld_s r15,[pcl,0x14]` al posto di
  `ld r15,[pcl,-24]` nel percorso Small; classificazione dei pool su due
  finestre (testa + target del `b_s`) perché il pool inghiotte la
  continuazione; dettagli lettori (`btst_s r0,0x1`). Integrazioni dell'audit
  (seconda esecuzione PASS): pool 0x235AE0=0x36A480 e asserzione della
  pre-guardia `bl_s 0x235ABC`; prologo completo di 0x149530 (`push_s r13`);
  attribuzione del pool 0x235868 alla funzione 0x235858; rami di fallimento
  del setter e della request documentati nell'evidenza JSON.

Verificatore: sha firmware e blocchi manifest verificati; 20 pool letti raw LE;
4 stringhe payload1 verificate byte per byte; 10 finestre GNU allineate salvate
in `gnu_windows.txt`; modello RMW su 65.536 valori; census completo dei 13 pool
e dei 5 gruppi di chiamanti; negativo AE→wire asserito.

## 6. Revisione indipendente (agente iris-actuation-audit, tools.agents.spawn, configurazione ereditata; atteso e integrato)

Ha riverificato tutti i claim con finestre allineate proprie e scansioni raw
(solo /tmp, nessuna scrittura nel progetto). Esito: **claim 1, 5 (MMIO iris),
7 (pannello), 8 (negativo BFS) CONFERMATI byte-exact**; claim 2/3/4/6 confermati
nella sostanza con precisazioni ACCOLTE nel verificatore e in questo rapporto:

- **0x149530**: prologo `push_s blink` + `push_s r13` (niente `bl 0x334130`,
  che è invece la prima chiamata di 0x18B85C); coda 0x149362 = epilogo
  millicode condiviso.
- **Rami di fallimento del setter distinti**: 0x235A1C fallito → ritorna il
  corrente senza 0x23524C; solo il fallimento di 0x235DA0 chiama 0x23524C(2);
  il ramo di fallimento della request passa per 0x18B9D4 (iris entrambi i bit
  + delay 500 via 0x2359B0, 0x23524C(2), 0x235DE8).
- **Pre-guardia della request (omissione trovata dall'audit)**: 0x235B28
  `bl_s 0x235ABC` confronta h con l'halfword [0x36A480]; mismatch → ritorno 0
  senza attuazione. Ora asserita nel verificatore (pool 0x235AE0=0x36A480).
- **Attribuzione corretta**: il pool 0x235868 («pulisci entrambi») sta nella
  funzione 0x235858, non 0x235824 (0x235824 è un wrapper busy-check che chiama
  0x235754); comportamento invariato.
- Controprove richieste: scansione a **passo 1 byte** dell'intero payload0 →
  esattamente le 13 word LE 0x0FF04024, tutte 4-allineate, nessun altro writer
  dei bit 3/4 oltre la famiglia iris (caveat 0x2349C0 maschera da registro);
  0x124F64/0x124F6C effettivamente letti a 0x124D4E/0x124DC8.
- Su claim 8 l'agente ha ripetuto il negativo con una BFS transitiva di 373
  funzioni dalla chiusura AE: zero hit wire; il nome Big/Small dei due percorsi
  GPIO poggia sull'encoding 1/9 (claim 1/7), non su etichette interne.

NB: lo strumento «task con agente explore» richiesto dal runner non esiste in
questo ambiente; usato spawn come nelle iterazioni precedenti.

## 7. Limiti

- Statico: nessun MMIO eseguito, nessun hardware, nessun runtime; NON_INSTALLARE.
- Il significato fisico dei bit3/4 di 0x0FF04024 (due linee di drive? polarità
  coil?) e dei bit0/1 di 0x0FEF0388 (enable/strobe) è **inferenza** dal pattern
  RMW, non provato elettricamente; 0x0FF04024 resta anche il registro lens-ready
  bit7 e il registro «tasto logico 2» bit0 della mappa RAM.
- La RMW a maschera registro in 0x2349C0 può toccare bit3/4 a runtime.
- Census su listato lineare: i siti della catena sono tutti riverificati in
  finestre dedicate, ma falsi positivi di branch vicino ai pool non sono
  esclusi a priori per i census periferici.
- Lato completamento NON verificato: chi attende la fine della mossa (byte di
  stato [0x36A464+6], evento 0x10 con 1|1<<25, handler mailbox 0x235AF8/0x235AE4,
  la 0x158D04 finale) è aperto; come pure il ruolo AE dei sibling che
  accendono/puliscono entrambi i bit.
- V1.1 campione locale vs macchina V1.0; indirizzi non portabili senza prova.
- Circa 10% di avanzamento funzionale invariato: nessuna applicazione avviata,
  nessuna foto prodotta.

## 8. Prossimo passo (non ripetitivo)

(a) Lato completamento: decodificare gli handler 0x235AF8/0x235AE4 e il consumatore
dell'evento 0x10 per stabilire quando la mossa iris è finita (byte [0x36A464+6]:
chi lo azzera?) — è il pezzo che serve al «ritorno pronto» del percorso
fotografico; (b) in alternativa, census dei chiamanti rimanenti di 0x149530 fuori
dal blocco AE (0xDB46C..0x324A8C, script diagnostici e cattura) per attribuire
chi altro impone l'indice iris. Entrambe offline e byte-verificabili.
