# S33 V1.1 — ingresso originale F7844 in CPU

**Data:** 2026-10-31. Prova GNU ARC700 con immagini di laboratorio e servizi simulati, senza fotocamera.

Il verificatore entra dall'inizio originale di `0xF7844` e prepara per entrambi i casi uno stato iride 9, un valore richiesto 1 in `0x38068F`, risorse disponibili e assenza di busy. Usa una chiamata vera con ritorno e verifica il ripristino della pila attraverso l'epilogo originale.

| Secondo argomento | Uscita intercettata | Stato dopo | Post registrati |
|---|---|---:|---:|
| 1 | ramo alternativo `0xF7952` | 9 | 0 |
| 0 | dopo il frammento iride, `0xF78E6` | 1 | 1, handler `0x235AE4` |

La traccia contiene due ingressi `0xF7844`, un ingresso `0xF78BE`, una chiamata `0x149550` e una a `0x18B954`. Per il selettore 0 il banco simula con successo acquisizione della risorsa e post; il contatore di generazione passa da `0x1234` a `0x1235`. Il ritorno del post non dimostra il completamento fisico.

La prova intercetta `0xF7952` e `0xF78E6` e prosegue all'epilogo originale: **le parti successive dei due rami non sono eseguite**. I servizi preliminari, le risorse e MMIO sono fixture. Non viene eseguito il chiamante completo `0xD6A80`; il valore richiesto è iniettato, non calcolato in questa prova. Non si dimostrano ordine naturale, scheduler, conservazione concorrente dello stato, calibrazione ottica, mappa dei pulsanti o significato Auto. Il percorso statico e le sue condizioni sono nel [rapporto precedente](S33_GUI_Iride_Ordine_Originale_Statico_20261031.md).

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_iris_original_entry_cpu.py`. Evidenza PASS: `Risultati/GUI_S33/iris_original_entry_cpu_20261031T210116501068Z/`, con trace, patch delle sole copie di laboratorio, snapshot del verificatore e hash del dump. Regressioni PASS: produttore/copia sintetici 5 casi `Risultati/GUI_S33/iris_exposure_producer_cpu_20261031T210121621440Z/` e controllo statico `Risultati/GUI_S33/iris_original_order_static_20261031T210121719871Z/`. **NON_INSTALLARE.**
