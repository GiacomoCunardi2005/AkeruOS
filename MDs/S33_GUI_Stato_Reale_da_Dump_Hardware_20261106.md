# Stato reale del sistema GUI Nikon V1.1 dal dump hardware

6 novembre 2026. Prima attività del [piano GUI](S33_Kernel_Scheduler_e_Tabelle_da_Dump_Hardware_20261106.md): ricostruire dal `MEMDUMP.BIN` (SHA-256 `c91888b2…6107`, [analisi](S33_MEMDUMP_Analisi_Dump_Hardware_20261106.md)) come la fotocamera organizza davvero finestre, eventi e timer. Metodo: lettura della RAM con Python, disassemblaggio GNU ARC700 delle routine direttamente dal dump, confronto con i blocchi firmware verificati e con i rapporti GUI già esistenti. Nessun firmware creato, dump originale non modificato, nessun accesso alla fotocamera.

Certezza: **A** = osservato nella RAM e coerente col codice; **B** = osservato nella RAM, ruolo dedotto dal codice; **C** = ipotesi. Il dump è un'istantanea non atomica di `[0, 0x0104074C)`.

## Percorso reale di un messaggio GUI

| Passo | Indirizzo | Evidenza | Certezza |
|---|---|---|---|
| Task `WindowMgr` (TCB `0x861C`, prio 18) in attesa su semaforo `'mswl'` | oggetto `0x374120`; TCB+0x30 | RAM: magic `0x6C77736D`, waiter = nodo `TCB+0xBC` | A |
| Ciclo del task: attende (`0x17BC24`), riceve un messaggio da 12 byte (`0x17BD4C`): word 0 = finestra/argomento, halfword +4 = id messaggio, word +8 = parametro | entry `0x15AF0C` | disassemblato dal dump | A |
| Smistamento `0x169E1C(finestra, msg, param)` | `0x169E1C` | disassemblato | A |
| Hook **pre**: puntatore letto da `[0x367800]` | RAM `0x367800` = `0x159158` | letto nella tabella `0x367800` | A |
| Se msg = `0x440F` → `0x1453E4`; se finestra = 0 e msg ∈ `[0x4400,0x47FF]` → finestra = **finestra attiva** (`0x1453F4`) | `0x1453F4` legge `[[0x14579C]]` | RAM: `0x14579C` → cella `0x366EA4` → `0x783AE8` | A |
| Procedura di finestra `0x169D78(finestra, msg, param)` che cerca il messaggio nella tabella dell'oggetto | `0x169D78` | non disassemblata qui (solo chiamata) | B |
| Hook **post**: `[0x367804]` | RAM `0x367804` = `0x159230` | letto | A |

Al momento del dump `WindowMgr` non aveva messaggi pendenti: la cella di stato `0x3673FC` ha halfword +4 e word +8 a zero. Gli stati `0x42B`/`0x42D` dei task in attesa sono quindi attese su oggetti, non lavoro in corso.

## Finestra attiva nel dump

`0x783AE8` è un oggetto in heap (fuori dal firmware): tipo `0x1342`, lista figli `0x783A1C` (14 puntatori nel blocco 3, già descritta), tabella messaggi → gestori a partire da `+0x20`: 39 coppie, tra cui `0x4401→0x659554`, `0x4405→0x65959C`, `0x4406→0x659EF0`, `0x4409→0x65A4A4`, `0x440E→0x659FA0`, `0x4110→0x65CC40`, `0x4111→0x65CCC8`, `0x2701→0x65C6B4`. Coincide con la finestra **AutoScene LiveView** già censita dai rapporti ([chiusura 0x4405](S33_GUI_AutoSceneLiveView_Close_Handler_4405_CPU_20261101.md), [scrittori 0x4110/0x4111](S33_GUI_AutoSceneLiveView_Append_Writers_4110_4111_CPU_20261101.md)): la fotocamera era nella schermata di ripresa. Certezza **A** per indirizzo e tabella; **B** per il nome della finestra (dedotto dai gestori).

## Descrittori noti

I cinque descrittori (`CaptureMenu 0x9802AC`, `Menu ISO 0x989FCC`, `Menu tempo 0x989CD8`, `GeneralSetupMenu 0x99242C`, `SoundSettingMenu 0x9A0A44`) sono nella RAM **identici al firmware** (primi `0x40` byte) e ciascuno è referenziato **una sola volta**, da una tabella nel blocco 1 (`0x3F5908`, `0x3F59FC`, `0x3F59F8`, `0x3F5BDC`, `0x3F5BF4`). Sono dati statici: **non provano** che quelle finestre fossero aperte. Certezza **A** (identità), **C** (uso).

## UIAux e UITimer

- **UIAux** (TCB `0xB91C`, entry `0x15B06C`): ciclo che attende su un gruppo di eventi `'nvel'` (`0x3732E4`) con maschera `0x2200001`/`0x200703`, chiama `[0x367408]` se non nullo e riarma gli eventi. In RAM `[0x367408] = 0x12F9B8`: callback registrata, quindi chiamata a ogni risveglio. **A**/**B**.
- **UITimer** (TCB `0xAF9C`, entry `0x149228`, stato `0x102` = attesa temporizzata senza oggetto, scadenza 371): ciclo che calcola i millisecondi trascorsi (periodo base 50 ms, `0xC350` µs) e scorre una **tabella di 40 timer a passo `0x1C`** a `0x443ADC` (flag attivo in halfword +6, countdown +0x14/+0x18, ricarica +0x0C, callback +0x10). Nel dump 11 voci hanno dati e 5 sono attive: voci 1, 4, 7, 9, 10 con callback `0x16EAF8`, `0x148F6C`, `0x177240` e due voci senza callback. **A** per la tabella, **B** per i campi.

## Punti di aggancio osservati per AkeruOS

Sono **candidati**, non verificati come scrivibili né come sicuri:

1. Hook pre/post del dispatcher a `0x367800`/`0x367804` (oggi con funzioni Nikon `0x159158`/`0x159230`: servirebbe concatenare, non sostituire).
2. Callback UIAux `[0x367408]`.
3. Tabella messaggi di una finestra (coppie `msg→gestore` nell'oggetto finestra).
4. Registrazione di un timer UI nella tabella `0x443ADC` (via `0x14905C` già censita).

## Limiti

- Un solo istante, non atomico; la finestra attiva è quella di ripresa, non il menu.
- `0x169D78` (ricerca nella tabella) non è disassemblata in questo rapporto: ordine di ricerca e comportamento sui messaggi non trovati restano da leggere.
- Il significato di stato `0x102` e dei campi della tabella timer è dedotto dal codice, non provato.
- Gli hook `0x367800` sono in area dati del blocco 1: non so se la loro scrittura sia sicura a runtime.
- Framebuffer e catena di disegno non sono in questo rapporto; potrebbero stare oltre `0x0104074C`.

**Prossimo:** disassemblare `0x169D78` e la ricerca nella tabella dei messaggi; seguire UIAux→`0x12F9B8`; poi la catena grafica (fase 3). Nessuna modifica al firmware della S33.

Coda messaggi e flusso evento → task → finestra: [dettaglio](S33_GUI_Coda_Messaggi_WindowMgr_da_Dump_20261106.md).

**Correzione (stessa data):** la regola di instradamento con finestra 0 è invertita in questo rapporto: con finestra 0 vanno alla finestra attiva gli id **fuori** da `0x4400–0x47FF`. Vedi [integrazione manager](S33_GUI_Integrazione_Manager_Nikon_e_Validazione_muludw_20261106.md).
