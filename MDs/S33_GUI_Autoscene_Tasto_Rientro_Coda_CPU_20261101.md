# S33 V1.1 — tasto logico AutoScene e rientro nel modello

**Data:** 2026-11-01. Nove sequenze GNU ARC700 PASS con manager Nikon originale, descrittore AkeruOS sperimentale e fixture. Nessuna esecuzione sulla fotocamera.

Il banco estende il [rientro con chiamata diretta](S33_GUI_Liveview_Rientro_Coda_CPU_20261101.md): dopo ISO → AutoSceneLiveView `0x783AE8`, consegna al dispatcher originale l'evento logico `0x700`. Un wrapper di laboratorio inoltra questo evento al callback originale AutoScene `0x6593A0`, mentre simula il lifecycle. Il percorso eseguito raggiunge `0x65C46C` → `0x65C5F8` e richiede al manager originale **ID 2, argomento 4**. I byte delle funzioni, della tabella eventi `0x783B08`, dei descrittori e della voce ID 2 sono confrontati con il dump. La tabella originale associa `0x700` all'handler `0x65C46C`.

| Condizione del banco | Esito osservato |
| --- | --- |
| Guardia del manager forzata | Il dispatcher restituisce 1, ma il descrittore rimane AutoScene e la coda rimane sospesa. |
| Guardia rimossa | Il dispatcher restituisce 1 e il manager rende corrente il descrittore AkeruOS sintetico. Dopo verifica del descrittore, il banco reinizializza e completa la coda; un successivo `0x700` instradato al modello apre la pagina colore. |

Il valore 1 del dispatcher significa evento gestito nelle condizioni provate: **non conferma da solo l'apertura**. Modalità `0x46`, letture dei tasti, alcune guardie e servizi sono fixture. Per questo esperimento la voce ID 2 della tabella oggetti è sostituita globalmente nella copia laboratorio con il descrittore sintetico: l'ID 2 originale continua a puntare a CaptureMenu nel dump. L'argomento 4 è quello osservato nell'handler, non la prova che il nuovo menu debba interpretarlo come una schermata specifica.

Il banco impone l'evento e poi resetta esplicitamente coda e schermata dopo il controllo dell'esito. Callback lifecycle e rendering live view sono simulati; dopo l'osservazione viene ripristinato artificialmente lo stato per i casi ereditati. Non sono stabiliti tasto fisico, selezione reale, apertura grafica, concorrenza, proprietà RAM o comportamento fotografico. Il percorso non implementa Mono RAW e non autorizza la sostituzione globale di ID 2.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_autoscene_key_reenter_cpu.py`; [rientro](../Risultati/GUI_S33/autoscene_key_reenter_cpu_20261101T095045Z/reentry.json), casi, trace, fixture, snapshot e hash nella stessa directory. Regressioni PASS: `liveview_reenter_queue_cpu_20261101T095054Z/` e `akeru_menu_model_20261101T095054Z/`. Il tentativo `autoscene_key_reenter_cpu_20261101T095002Z/` è conservato FAIL: una fixture e un file RAM con lo stesso nome si sovrascrivevano, causando un ciclo nel simulatore; il nome della fixture è stato corretto, senza modificare firmware o GNU. Nessuna operazione su fotocamera o SD; **NON_INSTALLARE**.
