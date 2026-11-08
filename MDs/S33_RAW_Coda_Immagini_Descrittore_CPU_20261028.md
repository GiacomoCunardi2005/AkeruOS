# S33 V1.1 — writer RAW e recupero del descrittore: prova CPU sintetica

28 ottobre 2026. **PASS su tre casi sintetici**, nel simulatore GNU ARC700 con modello DSP v7 sperimentale. Firmware originale usato per le istruzioni indicate, senza operazioni su fotocamera o SD. **NON_INSTALLARE**.

La prova concatena i controlli originali `0x1B9292` e il loro epilogo con la pubblicazione originale `0x18EE50 → 0x18E9D0`, quindi entra artificialmente nel frammento `0x18EFC2..0x18F00C`, che preleva il nodo e cerca il descrittore con `0x18E354` e lo promuove con `0x18E310`. Il writer, la coda e i lock sono fixture; il writer registra solo gli argomenti. Un trampolino di laboratorio termina il frammento prima del resto della preparazione immagini.

| Caso | Sequenza registrata | Risultato del frammento |
|---|---|---|
| Flag 1, nodo corrispondente | writer 1 → push 2 → pop 3; richiesti 26.527.232 byte | Il writer riceve `0x2040000`; il descrittore `0x2021000` viene ritrovato con dati `0x2040000` e passa da stato 1 a 2. |
| Flag 0, nodo corrispondente | nessun writer → push 1 → pop 2 | Stesso recupero e promozione del descrittore sintetico. |
| Flag 1, nodo con indirizzo differente | writer 1 → push 2 → pop 3 | Writer riceve `0x2040000`, nodo contiene `0x2041000`: ricerca fallisce, contesto elaborazione resta vuoto e descrittore resta in stato 1. L'uscita del frammento è intercettata a `0x18F252` con `r0=1`. |

Le tre prove impongono direttamente un descrittore, un nodo e stato `0x0A`, e partono dal gate RAW **dopo** il marcatore. La fixture a uno slot restituisce il nodo accodato; i numeri di sequenza sono registrati dalle fixture, non sono tempi hardware. L'epilogo originale restituisce la sentinella `123` impostata dal banco in `fp-188`, anche se il writer è stato chiamato; non è un risultato di scatto. Lo stack del gate è conservato. La prova del disaccordo mostra il controllo di corrispondenza in questa configurazione, non un errore osservato sul dispositivo.

Il puntatore dati non è dereferenziato e non è mappato un frame. Il frammento immagini è invocato direttamente con registri e contesto preparati, e l'uscita è sostituita in laboratorio: non sono eseguiti il suo vero ingresso `0x18EE98`, l'evento, UIAux, il confronto `0x1E2944`, il worker JPEG o servizi file. Non sono provati ordine dei task reali, durata del buffer, stesse immagini fisiche, formato, purezza o persistenza. Il verificatore usa copie di laboratorio dei blocchi con trampolini documentati: non modifica firmware o installazione GNU.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_queue_image_link_cpu.py`. [Casi](../Risultati/HiddenMenu_RAW/raw_queue_image_link_cpu_20261028T143726Z/cases.json), [istruzioni](../Risultati/HiddenMenu_RAW/raw_queue_image_link_cpu_20261028T143726Z/gnu_windows.txt), [fixture](../Risultati/HiddenMenu_RAW/raw_queue_image_link_cpu_20261028T143726Z/fixture_patches.json), [script](../Python_Trace_Scripts/s33_verify_raw_queue_image_link_cpu.py). Due avvii precedenti sono falliti per mappatura mancante e registro di prova sovrascritto dal frammento; restano conservati nelle rispettive cartelle. Il PASS non prova che le fixture corrispondano ai servizi fisici.
