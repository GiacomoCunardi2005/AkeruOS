# S33 — pool e descrittore: prova CPU con servizi sintetici

28 ottobre 2026. Firmware V1.1 originale, esecuzione offline nel simulatore GNU ARC700 con modello DSP sperimentale; cinque scenari sintetici PASS. La prova collega la costruzione di un nodo di coda all'assegnazione del suo puntatore a un descrittore, senza acquisire un'immagine. Rimane **NON_INSTALLARE**.

La sequenza chiama direttamente `0x18E4B4`, quindi `0x18ED60` con primo argomento zero. Sono originali anche `0x18E1C8`, `0x18E204`, `0x18E8B4` e gli helper aritmetici raggiunti. Regione, coda, sincronizzazione, riempimento, metadati e altre condizioni di servizio sono **fixture**; indirizzi e dimensioni sono scelti per il banco, non misurati. La coda fixture conserva in ordine i nodi pubblicati e restituisce il primo. Il codice originale e le finestre esaminate sono confrontati con il dump locale; l'immagine di laboratorio contiene esclusivamente trampolini documentati verso le fixture.

| Caso | Conteggio descrittori dato | Nodi prodotti | Esito acquisizione | Risultato osservato |
|---|---:|---:|---:|---|
| Nessun nodo | 2 | 0 | `0x40100003` | Il pool ritorna 0 ma non viene attivato; nessun nodo corrente. |
| Un nodo | 2 | 1 | 0 | Nodo `0x47D6D0`, descrittore sintetico `0x2400000`, stato 1, dati `0x240B000`. |
| Quattro nodi | 2 | 4 | 0 | Stessa associazione per il primo nodo. |
| Limite | 2 | 20 | 0 | La dimensione sintetica permette 30 nodi per divisione, il codice ne pubblica 20. |
| Nessun descrittore | 0 | 1 | `0x40100003` | Il nodo estratto rimane nel campo acquisizione corrente, ma la cella di uscita osservata resta zero. |

Nel caso riuscito il valore dati deriva dall'inizializzatore originale e arriva al campo `descrittore+4`; il valore `0x12345678` a `descrittore+8` proviene invece dalla **fixture metadati**, non da un sensore. I conteggi sono osservati dalla coda fixture. Il caso senza descrittore parte con cella di uscita zero e non prova da solo che una cella inizialmente nonzero sarebbe preservata; questo limite è distinto dalla precedente analisi statica degli errori.

Le dimensioni di regione, frame e riserve sono arbitrarie. Solo il tratto iniziale della regione sintetica è mappato per il descrittore: l'indirizzo dati viene **calcolato ma non dereferenziato**. Non sono provati capacità o mappa RAM fisiche, dati RAW, organizzazione CFA, portata del puntatore, durata del buffer, attivazione della pipeline, scatto o riuso in concorrenza. Lo scenario senza descrittore non dimostra una perdita reale di risorse. Nessuna modifica a firmware, GNU, fotocamera o SD.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_pool_descriptor_cpu.py`. [Script](../Python_Trace_Scripts/s33_verify_raw_pool_descriptor_cpu.py), [casi](../Risultati/Mono_RAW/pool_descriptor_cpu_20261028T090415Z/cases.json), [fixture](../Risultati/Mono_RAW/pool_descriptor_cpu_20261028T090415Z/fixture_patches.json), [disassemblato](../Risultati/Mono_RAW/pool_descriptor_cpu_20261028T090415Z/gnu_windows.txt). I tentativi iniziali falliti restano nelle relative directory di prova; quello con il simulatore standard ha incontrato un'istruzione DSP non supportata.
