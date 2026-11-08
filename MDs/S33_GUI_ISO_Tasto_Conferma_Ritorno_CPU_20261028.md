# ISO: tasto logico, conferma e ritorno — 28 ottobre 2026

Due sequenze GNU ARC700 passano dal tasto logico 11 e dalla coda originali al dispatcher, al controllo classe `0x15` con destinazione sintetica ISO `0x3F`, e al WindowManager originale. In entrambi i casi il descrittore corrente diventa quello diagnostico ISO `0x989FCC`. Dopo l'inizializzazione, il banco imposta esplicitamente la posizione selezionata in un controllo sintetico e consegna l'evento di conferma `0x4801` al dispatcher originale.

| Posizione iniettata | Record originale | Campi software iniziali | Dopo conferma | Descrittore corrente finale |
|---:|---|---|---|---|
| 7 | ISO 125, indice 6 | 88 / 77 / 555 | 6 / 6 / 125 | `0x987AF8`, DEBUG MODE MENU `0x36` |
| 0 | Exit, valore `-1` | 88 / 77 / 555 | 88 / 77 / 555 | `0x987AF8`, DEBUG MODE MENU `0x36` |

I campi sono rispettivamente byte `0x365787`, byte `0x367BC8` e halfword `0x37FBF2`. Per ISO 125 il callback e setter originali scrivono i valori; Exit li preserva. Il ritorno al menu diagnostico passa attraverso `0x1453E4` e `0x145180` originali, non solo una richiesta intercettata. L'oggetto `0x36` è verificato nella tabella originale. Questa sequenza conferma il problema di navigazione: il ritorno osservato **non** è al sottomenu esposizione desiderato.

Il primo e il secondo evento sono consegnati al dispatcher dal banco; la selezione del record è iniettata, non ottenuta navigando il controllo. Lista principale e controlli sono sintetici; lock, notifiche, filtro tasti, attributi, recupero risorsa diagnostica, selezione, testo e grafica sono fixture. Timer e altro stato RAM sono sintetici; DSP v7 sperimentale. Il primo tentativo [093109Z](../Risultati/GUI_S33/key_iso_confirm_transition_cpu_20261028T093109Z/) e il secondo [093117Z](../Risultati/GUI_S33/key_iso_confirm_transition_cpu_20261028T093117Z/) si sono fermati su aree sintetiche non mappate; le aree sono state aggiunte al banco finale senza modificare il firmware originale.

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_key_iso_confirm_transition_cpu.py), [risultati, trace, patch fixture e hash](../Risultati/GUI_S33/key_iso_confirm_transition_cpu_20261028T093139Z/). Il test confronta le finestre elencate e la lista con il dump V1.1 e verifica i campi, i descrittori e lo stack. Non dimostra pulsanti fisici, rendering, sensore, ordine AE o persistenza allo scatto; non rappresenta una GUI nuova né un percorso di installazione. **NON_INSTALLARE**.
