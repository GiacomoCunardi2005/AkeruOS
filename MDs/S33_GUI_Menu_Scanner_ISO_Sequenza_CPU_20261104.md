# Dal menu AkeruOS alla selezione ISO originale — CPU emulata

Data 2026-11-04; firmware V1.1. In uno stesso banco lo scanner, il generatore, il fan-out e la coda originali producono due pressioni con rilascio. I record sono estratti e consegnati esplicitamente al dispatcher originale: il callback di un descrittore sintetico invoca `akeru_menu_defer_event` del prototipo C compilato. La prima pressione logica `0x580` apre nel modello la pagina esposizione e produce `REDRAW`; il banco preleva l'azione. La seconda `0x700` produce `OPEN_ISO`; il banco preleva l'azione e, solo se il valore corrisponde, chiama il manager originale `0x1453E4(0x3F, 0)`. È il banco a interpretare l'azione, non un'integrazione automatica di produzione.

## Apertura

**4/4 casi PASS**, due ordini delle callback × guardia busy 0/1. Con busy 0 il manager originale rende corrente il descrittore ISO `0x989FCC`, esegue lifecycle e inizializzazione originali e richiede al selettore simulato la posizione 7 (indice software iniziale 6). Con busy 1 la finestra sintetica iniziale rimane corrente e la selezione ISO non viene chiamata. La richiesta del modello è prelevata in entrambi i casi: il recupero dell'azione in caso di rifiuto non è dimostrato qui.

## Navigazione e conferma dopo apertura

Altri **4/4 casi PASS**, due ordini × due direzioni, busy 0. La variante sostituisce lo stub del selettore con la funzione originale; il banco consegna il `0x4409` estratto (il suo handler è uno stub) e impone controllo attivo e attributi della lista. La selezione parte dalla posizione 7 (ISO 125):

| Evento di navigazione logico | Posizione | Indice software | Parametro scritto |
|---|---:|---:|---:|
| bit 20 / classe 7 | 7 → 6 | 5 | 120 |
| bit 16 / classe 8 | 7 → 8 | 7 | 140 |

Lo scanner originale genera poi pressione/rilascio classe 11; il controllo originale genera `0x4801`, e callback ISO, getter, convertitore e setter originali aggiornano i valori. La posizione non è imposta nel banco. Le tracce e gli assert verificano la catena, compreso il callback sintetico iniziale. Le finestre originali collegate sono confrontate byte per byte dopo il link; modello e descrittore sono sintetici.

## Limiti

La finestra AkeruOS iniziale è imposta corrente, non aperta; il banco prende manualmente le azioni del modello, estrae i record e invoca il dispatcher. Stato, ordine callback, coda, controllo, focus e servizi di sistema sono fixture o stub; il manager di ritorno è bloccato imponendo count tabella zero. Non sono dimostrati ritorno al menu, gestione del rifiuto, concorrenza, rendering, assegnazione dei tasti fisici, sensore, esposizione automatica o persistenza. I valori ISO sono parametri software, non una prova di sensibilità fisica. Nessun dispositivo, supporto o firmware originale modificato. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_key_scanner_menu_iso_open_cpu.py` ([4/4](../Risultati/GUI_S33/key_scanner_menu_iso_open_cpu_20261104T113502584969Z/verified_evidence.json)) e `python3 Python_Trace_Scripts/s33_verify_key_scanner_menu_iso_navigation_cpu.py` ([4/4](../Risultati/GUI_S33/key_scanner_menu_iso_navigation_cpu_20261104T113502606743Z/verified_evidence.json)). Regressione ponte menu [49/49](../Risultati/GUI_S33/key_scanner_menu_bridge_cpu_20261104T113502588426Z/verified_evidence.json).
