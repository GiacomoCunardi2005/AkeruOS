# Catena grafica del testo Nikon dal dump hardware (fase 3, parziale)

6 novembre 2026. Terza attività del piano GUI (`goal.txt`, [stato GUI](S33_GUI_Stato_Reale_da_Dump_Hardware_20261106.md), [coda messaggi](S33_GUI_Coda_Messaggi_WindowMgr_da_Dump_20261106.md)): capire come Nikon disegna il testo, dal `MEMDUMP.BIN` (SHA-256 `c91888b2…6107`). Metodo: disassemblaggio GNU ARC700 delle routine direttamente dal dump e lettura dei puntatori/tabelle in RAM. Nessun firmware creato, dump intatto, nessun accesso alla fotocamera. Certezza **A** (osservato in RAM e coerente col codice), **B** (dedotto dal codice), **C** (ipotesi). Istantanea non atomica di `[0, 0x0104074C)`.

## Risultato: la grafica è un driver a callback, non una scrittura diretta

| Livello | Funzione | Cosa fa | Evidenza | Certezza |
|---|---|---|---|---|
| 1 | `0x186D08(x0,y0,x1,y1, testo, colore, flags)` | disegna una stringa in un rettangolo (coordinate halfword sullo stack), allineamento da `flags` (bit 2 centrato, bit 3 a destra) | disassemblata fino al ritorno | A |
| 1a | contesto di disegno `0x20E320` → `[0x20E3A0]` = `0x3E8950` | se `ctx+0x10` è 0 o 2 usa dimensioni schermo `0x20DBC8` e clip `0x20D7BC/0x20D860`, altrimenti rettangolo da `[ctx+0x14]`+8/+0xA | disassemblata | A |
| 1b | dimensioni dello schermo | contesto `[0x20DB70] = 0x3696A8`: larghezza **640**, altezza **480** (halfword `+0x12`/`+0x14`, copia a `+0xE`/`+0x10`) | RAM | A |
| 2 | **tabella callback grafica** `[0x187010] = 0x367F30` | `+0` **imposta colore** (`0x23E7D8`, argomenti = 4 byte di `colore`), `+4` **pre-disegno** (`0x23EA4C`, argomento = `flags`), `+8` = `0x18067` (non attribuito) | RAM | A |
| 3 | `0x186C40(testo, riga, flags, callback, rettangolo)` | scorre le righe (`0x186B14` spezza il testo, riconoscendo anche caratteri a 2 byte via `0x23AD30`) e per ogni riga chiama `jl [callback]` | disassemblata | A |
| 4 | **callback di riga** `[0x187018] = 0x1870DC` | calcola la X di una riga in base all'allineamento (usa la larghezza stringa `0x186864`) e prosegue verso il disegno dei glifi | inizio disassemblato | B |

Catena di chiamata reale: `0x186D08` → pre-disegno `[tabella+4]` e colore `[tabella+0]` → `0x186C40` → `0x186B14` per riga → callback `0x1870DC`. Il **registratore** dei test del 5 novembre sostituiva la parte oltre il callback.

## Colore e attributi

- `0x23E7D8` (imposta colore) chiama `0x23EA28` e `0x23ABA4` con i 4 componenti (probabile conversione verso l'hardware OSD: **C**).
- `0x23EA4C` (pre-disegno) estrae dal word `flags` i bit 4, 5, 7 e 8 e li passa a `0x23E854`, `0x23E8D4`, `0x23E784` (stile/attributi del testo: **C**).

## Non ancora trovato

- **Dove finiscono i pixel:** il callback `0x1870DC` e le funzioni sotto (`0x23ABA4`, `0x23EA28`, funzioni di glifo) non sono ancora lette; il buffer di destinazione e il formato dei pixel sono ignoti. Non c'è ancora un puntatore a framebuffer.
- **Aggiornamento del display:** quale funzione rende visibile il disegno non è identificata.
- **Dimensione 640×480:** è la dimensione *logica* del contesto; la risoluzione fisica dell'LCD può essere diversa (non verificata, **C**).

## Come usarlo per AkeruOS

AkeruOS può chiamare `0x186D08` con rettangolo, stringa, colore e flags (stesso percorso Nikon), senza accedere ai pixel: sarà il driver a tradurre. È una **proposta (C)**, non verificata né eseguita; nel dump la tabella callback è in dati del blocco 1 e potrebbe essere inizializzata a runtime.

## Limiti

- Un solo istante; framebuffer possibile oltre `0x0104074C`, quindi fuori dal dump.
- `0x1870DC` letta solo nella prima parte; `0x186CE4` e le funzioni di glifo non lette.
- Nessun test in emulatore in questa iterazione: le fasi 4 e 5 del piano non sono state eseguite.

**Prossimo:** seguire `0x1870DC` fino al disegno del glifo, `0x23ABA4`/`0x23EA28`, e cercare nel codice il puntatore al buffer; poi la fase 4 (profilo emulatore dal dump). Nessuna modifica al firmware della S33.

Profilo di emulazione dal dump e primo disegno: [dettaglio](S33_GUI_Profilo_Emulatore_da_Dump_e_Primo_Disegno_20261106.md).
