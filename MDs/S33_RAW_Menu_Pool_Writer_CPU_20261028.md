# S33 V1.1 — impostazione RAW, pool e writer in una prova CPU

28 ottobre 2026. Tre scenari GNU ARC700 con modello DSP sperimentale; **NON_INSTALLARE**. Il banco usa l'evento HiddenMenu originale `0x500C` per selezionare il flag RAW e il modo 3, poi chiama direttamente il produttore di stato originale e il pool originale, quindi entra artificialmente nel gate del writer. Chiamante, ordine, flag iniziali, regione, code e servizi sono sintetici; il writer registra solo puntatore e lunghezza. Non viene eseguito il marcatore.

| Caso | Stato prodotto | Flag / modo | Distanza nodi | Writer |
|---|---:|---|---:|---|
| On | `0x0A` | 1 / 3 | 13.263.872 | 26.527.232 byte dal primo nodo |
| Off | `0x0A` | 0 / 0 | 13.263.872 | non chiamato |
| On | `0x0B` | 1 / 3 | 13.263.872 | 26.527.232 byte dal primo nodo |

Nel primo caso la lettura richiesta oltrepasserebbe l'inizio del secondo nodo di 13.263.360 byte se un servizio reale leggesse l'intero intervallo e se la geometria sintetica rappresentasse il runtime. Il banco non mappa né legge i dati pixel, e la chiamata artificiale del gate nel caso `0x0B` non prova che quello stato vi giunga realmente. Non dimostra capacità fisica, concorrenza, corruzione o comportamento del dispositivo; rafforza la necessità di non installare il candidato senza risolvere la capacità reale.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_menu_pool_writer_cpu.py`. [Casi](../Risultati/Mono_RAW/menu_state_pool_writer_cpu_20261028T145046Z/cases.json), [fixture](../Risultati/Mono_RAW/menu_state_pool_writer_cpu_20261028T145046Z/fixture_patches.json), [script](../Python_Trace_Scripts/s33_verify_raw_menu_pool_writer_cpu.py). Due tentativi precedenti si sono arrestati rispettivamente per allineamento assembly e sovrapposizione mappe; corretto solo il banco. Il valore stack registrato riguarda la sequenza produttore/pool; il gate termina artificialmente e il banco ripristina lo stack, senza testarne l'epilogo.
