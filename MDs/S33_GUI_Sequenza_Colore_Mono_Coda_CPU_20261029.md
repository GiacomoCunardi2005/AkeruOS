# GUI — sequenza principale, mono e ritorno al colore

Il 29 ottobre 2026 ho eseguito una sequenza continua con stato modello inizializzato una sola volta. Nel [banco GNU ARC700](../Python_Trace_Scripts/s33_verify_gui_descriptor_color_sequence_cpu.py), uno scrittore di tasti logici e la coda originali generano pressioni e controparti; il banco estrae ogni record e lo consegna al dispatcher originale, che chiama il callback di un descrittore sintetico. Il callback usa il ponte C di selezione colore/mono.

| Passo | Evento logico | Schermata dopo l'evento | Azione | Modalità dopo pressione e rilascio |
|---|---|---|---|---|
| Apri colore dal menu principale | `0x700` | colore | ridisegno | standard |
| Seleziona mono | `0x2180` | colore | richiesta mono | mono |
| Torna al menu principale | `0x580` | principale | ridisegno | mono |
| Riapri colore | `0x700` | colore | ridisegno | mono |
| Seleziona standard | `0x700` | colore | richiesta standard | standard |

**Cinque passi PASS** nella stessa sequenza, con cinque rilasci, record di coda, stato, azioni, modalità e stack verificati. Dopo ogni pressione il banco elabora lo stesso frame sintetico 2×2: in standard l'output sentinella rimane 777, in mono i quattro campioni 1024 diventano 1219; l'input resta invariato. [Casi](../Risultati/GUI_S33/descriptor_color_sequence_cpu_20261029T225046Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/descriptor_color_sequence_cpu_20261029T225046Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/descriptor_color_sequence_cpu_20261029T225046Z/fixture_patches.json).

Il descrittore è senza risorse grafiche; eventi e consegna sono imposti dal banco, RAM e MMIO sono sintetici, lock e altri servizi sono fixture. La modalità è mantenuta per la durata della sequenza in memoria sintetica, non è verificata dopo riavvio o cambio modalità reale. Non è provata la mappa dei tasti fisici, l'integrazione con lo scatto, JPEG o display. Mono usa parametri sperimentali non calibrati; **NON_INSTALLARE**.
