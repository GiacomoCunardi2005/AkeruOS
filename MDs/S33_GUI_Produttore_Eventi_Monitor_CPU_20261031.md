# S33 — produttore eventi e monitor, 31 ottobre 2026

Nel firmware V1.1 il produttore `0x242040` legge uno stato tramite `0x2D6200`: per il bit 0 chiama `0x158CBC` con ID `0x3200002` e maschera `0x100`, per il bit 1 con lo stesso ID e maschera `0x200`; poi passa lo stato a `0x2D6214`. Questo percorso era stato individuato staticamente nella [ricostruzione dei consumer](S33_Iride_Consumatori_Registrazioni_Evento_3200002.md).

La variante `--producer` del [banco](../Python_Trace_Scripts/s33_verify_gui_monitor_rearm_four_routes_cpu.py) esegue ora anche `0x242040`: il getter di stato e l'ack sono fixture, come il servizio di notifica, che registra solo le maschere inviate all'ID `0x3200002`. **Il banco consegna esplicitamente** la maschera registrata a `0x242104`; non esegue attesa, accodamento o risveglio del task.

Dopo l'attivazione iniziale, la maschera combinata e il callback timer imposti dal banco, ogni sequenza predispone tre stati del produttore: `1`, `2`, `1`. Sono registrate rispettivamente coppie stato/ack e maschera `1/0x100`, `2/0x200`, `1/0x100`. Il primo `0x100` trova il monitor a modo 1 e lascia la coda vuota; `0x200` riarma; il successivo `0x100` porta all'evento logico di rilascio atteso. Quattro slot × due destinazioni alternative, **8 sequenze PASS** con tre controlli aggiuntivi: [evidenze](../Risultati/GUI_S33/monitor_producer_four_routes_cpu_20261031T154338Z/verified_evidence.json), [argomenti registrati](../Risultati/GUI_S33/monitor_producer_four_routes_cpu_20261031T154338Z/producer_events.bin), [fixture](../Risultati/GUI_S33/monitor_producer_four_routes_cpu_20261031T154338Z/fixture_patches.json). Le finestre del produttore e del monitor sono confrontate col dump; il DSP GNU è sperimentale.

Il banco non dimostra che gli stati 1/2 corrispondano a pressioni o livelli reali, né che siano prodotti in quell'ordine. Callback timer, stato, notifica, ack e recapito sono imposti o simulati; scheduler, periferica, concorrenza e pulsanti fisici non sono osservati. Non è dimostrata una perdita o una ripetizione fisica. **NON_INSTALLARE**.

## Controlli riuniti

`python3 Python_Trace_Scripts/s33_check_gui_offline.py` esegue mapping statico, modello menu, test mono e quattro varianti del monitor; ogni esecuzione scrive un riepilogo JSON e log separati in una nuova cartella. La prima esecuzione è [PASS](../Risultati/GUI_S33/checks_offline_20261031T154335124381Z/summary.json), con sette comandi riusciti. Il risultato riporta soltanto ciò che quei controlli coprono e non attesta funzionamento su fotocamera.
