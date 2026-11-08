# S33 V1.1 — rientro al menu e coda nel banco CPU

**Data:** 2026-11-01. Prova GNU ARC700 con manager originale e stato, descrittore e servizi in parte sintetici. Non è un'integrazione installabile.

Il banco estende la [prova di uscita ISO](S33_GUI_ISO_Verifica_Dopo_Transizione_CPU_20261101.md). Dopo che `0x2180` ha portato il descrittore corrente alla live view `0x783AE8`, il flag di ritorno sintetico è zero e la coda AkeruOS è ancora sospesa nella schermata esposizione.

Il banco chiede **direttamente** al manager originale `0x145180` di aprire il descrittore AkeruOS sintetico `0x2050000`, prima con la guardia del manager forzata e poi senza:

| Tentativo | Ritorno / descrittore corrente | Coda osservata |
| --- | --- | --- |
| Guardia forzata | 0 / live view | ancora sospesa, schermata esposizione, zero eventi in attesa |
| Guardia rimossa | 1 / descrittore sintetico | il banco reinizializza la schermata principale e completa con scarto |

Solo dopo aver controllato entrambi il ritorno e il descrittore, il banco imposta `AKERU_MAIN` e chiama `akeru_menu_complete(..., 1)`. Quindi consegna `0x700` al dispatcher originale `0x169E1C`: il callback sintetico accoda/estrae l'evento, il modello emette `AKERU_REDRAW` e passa alla schermata colore. È navigazione del modello, non selezione né elaborazione Mono RAW.

La reinizializzazione e il segnale di completamento sono **imposti dal banco**, non collegati a un callback di lifecycle reale. L'apertura da live view è una chiamata diretta del banco: non si dimostra quale pulsante fisico la provochi. Il descrittore non ha risorse grafiche, il callback live view è simulato, il controllo attivo è nullo e la consegna dell'evento è esplicita. Dopo l'osservazione, il banco ripristina artificialmente coda e descrittore per eseguire i controlli ereditati: non è una sequenza naturale verificata. Concorrenza, fallimenti diversi dalla guardia, rendering, ritorno fisico e ownership restano aperti.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_liveview_reenter_queue_cpu.py`; [risultati rientro](../Risultati/GUI_S33/liveview_reenter_queue_cpu_20261101T094754Z/reentry.json), nove casi, trace, fixture, hash e snapshot nella stessa cartella. Regressioni PASS: `iso_return_after_transition_cpu_20261101T094802Z/`, modello menu host/GNU `akeru_menu_model_20261101T094802Z/`. Tentativi `...094719Z` e `...094728Z` conservati FAIL: il banco non ripristinava rispettivamente un registro e lo stato schermata dopo la sottoprova. Nessuna modifica a firmware originale, GNU, fotocamera o SD; **NON_INSTALLARE**.
