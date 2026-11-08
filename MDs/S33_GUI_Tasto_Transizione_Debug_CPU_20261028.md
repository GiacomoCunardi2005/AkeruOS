# Tasto logico e transizione diagnostica — 28 ottobre 2026

Due casi GNU ARC700 eseguono in sequenza il tasto logico 11 in stato 1, inserimento ed estrazione dalla coda, il dispatcher `0x169E1C`, il controllo classe `0x15` e l'apertura originale `0x1453E4` → `0x145180`. Il banco consegna esplicitamente il record estratto al dispatcher e predispone `CaptureMenu` come oggetto corrente e una lista sintetica come controllo attivo.

| Record sintetico dello slot 0 | Descrittore corrente dopo la transizione | Inizializzazione osservata |
|---|---|---|
| ISO `0x3F` | `0x989FCC` | Il callback diagnostico richiede selezione della posizione 1 alla fixture, con stato ISO iniziale zero. |
| Tempo `0x3E` | `0x989CD8` | Il callback diagnostico passa la stringa `AUTO` alla fixture di testo. |

Il manager e i callback di inizializzazione sono originali; le richieste di selezione e testo sono intercettate, non eseguite sul display. Le otto risorse diagnostiche ricevono il puntatore al rispettivo descrittore nelle copie di laboratorio. L'evento per stato logico zero viene estratto separatamente ma non consegnato al dispatcher. Stack, risultato manager e inizializzazione attesa sono verificati nel banco.

Le due destinazioni sono **alternative**, non un sottomenu che contiene entrambi i controlli. Le schermate diagnostiche tornano a `DEBUG MODE MENU`: questa prova non realizza un ritorno alla GUI desiderata. L'apertura originale è eseguita, ma sincronizzazione, filtro tasti, attributi forzati a 2, lookup risorsa diagnostica, selezioni e disegno sono fixture; contesto, lista, gate e manager sono sintetici. Modello DSP GNU v7 sperimentale. Il ciclo scheduler, i pulsanti fisici, f/, sensore e persistenza restano non verificati.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_key_debug_transition_cpu.py), [risultati e fixture](../Risultati/GUI_S33/key_debug_transition_cpu_20261028T092827Z/). Le finestre elencate nello script sono confrontate con il dump V1.1; nessuna operazione su fotocamera o SD. **NON_INSTALLARE**.
