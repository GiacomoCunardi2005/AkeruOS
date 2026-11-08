# S33 — coda sperimentale e transizioni di schermata

**Data:** 2026-10-31. Modello offline AkeruOS; non è una modifica installabile al firmware Nikon.

La coda precedente conservava pressioni durante un'azione esterna e le interpretava al completamento nel menu AkeruOS precedente. Per esempio, una pressione destinata alla schermata ISO poteva diventare una richiesta di apertura iride al ritorno. Il rischio è una proprietà del modello precedente, non un evento osservato sulla fotocamera.

Il modello ora tratta `OPEN_ISO`, `OPEN_APERTURE`, `OPEN_SHUTTER`, `OPEN_SETTINGS` e `RETURN_LIVEVIEW` come trasferimenti di contesto: quando estrae una di queste azioni scarta le pressioni già accodate; durante il trasferimento `akeru_menu_enqueue` restituisce 0, senza consumare o accodare l'evento. Il chiamante deve instradarlo al proprietario effettivo. Deve chiamare `akeru_menu_complete` solo al ritorno nel menu o se l'apertura fallisce: l'avvenuta richiesta o la sola apertura non equivalgono a ritorno. Le azioni interne, inclusi redraw e flash, mantengono la coda sequenziale precedente; overflow resta esplicito. Lo scarto può perdere pressioni già arrivate prima del cambio di contesto: è una scelta conservativa nel prototipo, da rivalutare quando saranno noti ownership e ordine reali.

## Verifiche

- `make -C AkeruOS menu-model-verify`: PASS host e GNU ARC700, incluse tutte e cinque le transizioni esterne, scarto dei messaggi in attesa, mancato consumo dei nuovi eventi e ripresa esplicita. `Risultati/GUI_S33/akeru_menu_model_20261031T210231Z/`.
- `s33_verify_gui_manager_deferred_action_cpu.py --queued`: 12 casi PASS e sequenza originale di coda/dispatcher con fixture; la seconda pressione preaccodata viene ora scartata al rilascio dell'azione di apertura. `Risultati/GUI_S33/manager_buffered_menu_cpu_20261031T210246Z/`.
- Variante senza coda: 12 casi PASS `manager_deferred_menu_cpu_20261031T210251Z/`; flash con snapshot simulato: 6 PASS `flash_model_snapshot_cpu_20261031T210251458805Z/`; pipeline colore host/GNU PASS `akeru_color_pipeline_20261031T210251Z/`.

Il primo rilancio integrato `manager_buffered_menu_cpu_20261031T210237Z` ha evidenziato aspettative storiche non aggiornate per la quarta voce della pagina esposizione: ora apre la seconda pagina con redraw. Dopo la correzione di quelle aspettative il secondo tentativo `...210243Z` ha evidenziato la variazione intenzionale dello scarto; l'oracolo è stato aggiornato e il rilancio successivo è PASS. Entrambi i tentativi restano conservati come FAIL.

La prova integrata usa callback e contesto sintetici, non prova routing reale, apertura/chiusura, concorrenza o associazione fisica dei tasti. Il singolo slot differito separato non è trasformato in un sistema con ownership: qualsiasi integrazione deve usare un contratto coerente con il manager effettivo. Non sono state verificate installazione, persistenza, cattura o proprietà dell'hardware. **NON_INSTALLARE.**
