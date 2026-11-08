# Coda, dispatcher e ricaduta sul menu padre — 28 ottobre 2026

Otto casi GNU ARC700 passano dal generatore di eventi per i tasti logici 11, 14, 67 e 78 alla coda originale; il banco estrae il record e ne passa destinatario, evento e argomento al dispatcher originale `0x169E1C`. Quest'ultimo ricava il descrittore corrente tramite `0x1453F4`, usa `0x169D78`/`0x16A6E4` per raggiungere il controllo attivo e, attraverso lookup classe e wrapper `0x631610`, seleziona lo slot. Descrittore corrente, controllo attivo, tabella classe e condizioni del banco sono predisposti in RAM sintetica.

| Evento stato 1 | Slot sintetico | Richiesta registrata al servizio apertura |
|---|---:|---|
| `0x0580` | 0 | `0x3F` oppure `0x3E` nelle due varianti |
| `0x0700` | 1 | `0xBB` |
| `0x2180` | 2, destinazione record zero | `0x87`, argomento 0, dalla ricaduta sul menu padre |
| `0x2700` | 3 | `0xB7`, argomento 1 |

Nel caso `0x2180`, il controllo seleziona il terzo slot ma il suo handler restituisce zero perché la destinazione del record è zero. Il dispatcher prosegue dunque sul descrittore originale `CaptureMenu` `0x9802AC`: il wrapper `0x7CAFE8` raggiunge il percorso comune `0x20E940` che, nelle condizioni sintetiche provate, richiede `0x1453E4(0x87,0)`. L'ID è associato a `AutoSceneLiveView` nella [precedente verifica](S33_GUI_CaptureMenu_Ritorno_LiveView_CPU_20261027.md). La richiesta è catturata da una fixture, quindi l'apertura effettiva non è provata. Questo risultato **non** consente di usare una destinazione zero per garantire che il terzo slot rimanga inattivo.

L'estrazione e la chiamata a `0x169E1C` sono orchestrate dal banco; il ciclo permanente del WindowManager `0x15AF0C` e lo scheduler non sono eseguiti. Gli eventi per stato logico zero sono generati ed estratti ma non inoltrati al menu. Sono fixture sincronizzazione, notifica, filtro, selezione, attributi e apertura, elencate nell'evidenza; il modello DSP è sperimentale. Le finestre di codice e dati elencate dallo script sono confrontate con il dump V1.1. Il primo tentativo [092613Z](../Risultati/GUI_S33/key_queue_manager_dispatch_cpu_20261028T092613Z/) ha rivelato la ricaduta fallendo l'aspettativa precedente; è conservato come prova non ammessa. [Script](../Python_Trace_Scripts/s33_verify_gui_key_queue_manager_dispatch_cpu.py), [risultati PASS](../Risultati/GUI_S33/key_queue_manager_dispatch_cpu_20261028T092647Z/).

Le prove non identificano gli interruttori fisici, non verificano polarità, rendering, apertura reale, modifica delle impostazioni, salvataggio o fotocamera. ISO e tempo restano due varianti alternative, non un sottomenu; il menu colore originale non è Mono RAW Luminance. **NON_INSTALLARE**.
