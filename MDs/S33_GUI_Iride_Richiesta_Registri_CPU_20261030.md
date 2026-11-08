# GUI — richiesta iride e registri simulati

Il 30 ottobre 2026 ho esteso il [banco modello → pannello iride](S33_GUI_Modello_Richiesta_Iride_CPU_20261029.md): ora esegue anche la richiesta originale `0x235B0C` e, nei casi non occupati, il percorso originale Big `0x2358F4` o Small `0x235950`. Il modello C riceve l'evento logico sintetico `0x2180`; il banco interpreta la sua azione e chiama direttamente il dispatcher diagnostico `0x2C4FAC(0x50)`, che richiama pannello e setter originali.

I registri sono regioni di memoria inerti del simulatore, inizializzate dal banco a `0xA5A7` per `0x0FEF0388` e `0xA5B8` per `0x0FF04024`; non sono letture dalla fotocamera.

| Stato iniziale | Tasto logico sintetico | Condizione richiesta | Stato software finale | `0x0FEF0388` finale | `0x0FF04024` finale |
|---:|---:|---|---:|---:|---:|
| 9 | 9, Big | non occupata | 1 | `0xA5A4` | `0xA5B0` |
| 1 | 10, Small | non occupata | 9 | `0xA5A4` | `0xA5A8` |
| 9 | 9, Big | occupata | 9 | `0xA5A7` | `0xA5B8` |
| 1 | 10, Small | occupata | 1 | `0xA5A7` | `0xA5B8` |

Nei casi non occupati il codice originale pulisce i bit 0/1 del primo registro sintetico; nel secondo pulisce i bit 3/4 e poi imposta rispettivamente bit 4 o bit 3. Nei casi occupati non raggiunge i due percorsi e scrive `0x15` in un byte di stato sintetico; la fixture di cleanup viene chiamata. Un quinto caso inietta nel modello l'evento ISO `0x700`: il banco non invoca il dispatcher iride e i registri sintetici restano ai valori iniziali. In tutti i casi sono controllati azione, risultato, stato, sentinelle osservate e stack; la traccia conta quattro ingressi alla richiesta originale e un ingresso per ciascun percorso Big/Small.

Il getter dei tasti riproduce una sequenza sintetica. Acquisizione e guardia del setter, verifica occupazione, lock, evento, mailbox, attesa, release, cleanup e disegno sono fixture; handle, stato e MMIO sono predisposti dal banco. In particolare, la condizione occupata è **imposta**, non osservata su hardware. La scritta del pannello è richiesta prima dell'esito e il ritorno del dispatcher non prova la commutazione; lo stato software e la scrittura simulata non provano movimento ottico o valori f/.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_model_iris_request_mmio_cpu.py), [manifest e traccia](../Risultati/GUI_S33/model_iris_request_mmio_cpu_20261030T103000Z/verified_evidence.json), [casi](../Risultati/GUI_S33/model_iris_request_mmio_cpu_20261030T103000Z/cases.json). Due preparazioni precedenti (`102916Z`, `102929Z`) non hanno avviato il simulatore perché i mapfile non coprivano il padding richiesto; il banco finale usa regioni allineate.

Non sono verificati mapping dei tasti fisici, WindowManager, registri reali, lente, concorrenza AE o scatto. Firmware e dispositivo invariati; **NON_INSTALLARE**.
